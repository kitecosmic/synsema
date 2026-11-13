# fancy-regex 0.20.2, with the Synsema patch

This folder is the source of the [`fancy-regex`](https://github.com/fancy-regex/fancy-regex) crate,
version 0.20.2 as published on crates.io (checksum
`0a2e16b9a584b602f1e0e5e22c30ca0906786088c27500653e432d086def8b53`, upstream commit
`6a7321d3fd38ab603d6e7e973c0fb152dbbdb307`), plus one patch. It is MIT licensed (`LICENSE`,
`AUTHORS`); the patch is distributed under the same license.

`synsema-stdlib` takes this folder by path (`engine/Cargo.toml`, `[workspace.dependencies]`), and
nobody else does: the other crates of the build that ask for `fancy-regex` (`tokenizers` 0.23 asks
for 0.17.0, `candle-transformers` 0.11 for 0.18.0) get the ones of crates.io as published. There is
no `[patch.crates-io]`. In a 0.x crate a new minor version can change what a pattern means, and the
patterns of a tokenizer were written for the version its crate asks for.

The patch adds methods, five error variants (to enums that are `#[non_exhaustive]`) and options
that are off by default. In the hidden `internal` module, which upstream keeps for its own
example, it adds fields to `CompileOptions` and `OptimizeOptions` (both have `Default`, and the
example builds them with `..Default::default()`) and changes the type of one field of an
instruction (`Delegate::inner`, item 2). With every option off, what a pattern matches is the same as upstream
except in the twelve places listed under "What a pattern matches".

## Why a fork

`backtrack_find_all`, `backtrack_capture`, `backtrack_replace` and `backtrack_matches` (v0.6.60)
promise that a call is an error the program can catch, and not a hang or the end of the process,
when the pattern does too much work or needs too much memory. Upstream does not give a caller what
that takes:

- **Work.** The limit upstream offers (`backtrack_limit`) counts how many times the VM backtracks.
  The work between two backtracks has no bound: with look-arounds inside repetitions,
  `(?:(?=(?:(?=[^x]*y)a)*+y)a)*+y` ran for 9 seconds on 3 200 characters and backtracked 3 202
  times (measured with 0.18.0; audit of v0.6.60, round 1). Counting the work needs a counter
  inside the VM loop, and upstream has no hook for it.
- **Size.** Upstream compiles a subroutine call (`\g<1>`) by copying the group it calls in place,
  up to 19 levels deep: `(a|b\g<1>\g<1>)`, 15 bytes, compiled to 649 MB, and with one more call it
  did not end (0.18.0; round 2). Since 0.20 upstream has `max_prog_size`, which bounds the number
  of instructions; it does not count what an instruction owns (the regex of a piece handed to the
  linear engine), which is where the bytes are.
- **What a search needs.** Each piece of a pattern that goes to the linear engine has a search
  cache that nothing counts. A part of it does not depend on the text (the table the linear engine
  follows capture groups with: states × capture slots), and a part grows as the text is read (the
  states of the lazy DFAs): a pattern of 9.6 KB with 400 pieces held 431 MB after one search
  (0.18.0; round 3), and 60 groups over `\w` ask for 36 MB the first time they search (round 4).
- **Panics and crossed groups.** A group that a look-ahead or a subroutine call enters again
  further back comes out with the start of one match and the end of another, and when the start
  is after the end, reading the group panics (still so in 0.20.2: `(?=b\g<1>)((?=))` on `b`).

## What the patch changes

Everything the patch adds is marked with a `Synsema:` comment. The whole patch is
`synsema.patch` (a unified diff against the published sources, 10 files).

1. **A step budget (`src/vm.rs`, `src/lib.rs`, `src/error.rs`).**
   - `Regex::find_input_with_steps(input, &mut steps)` and
     `Regex::captures_input_with_steps(input, &mut steps)`, with the two `*_from_pos_with_steps`
     over them. `steps` is what the search may spend; it comes back with what is left, so several
     searches can share one budget.
   - Every instruction the VM runs takes one step. An instruction that reads a stretch of the text
     takes one more step for every 16 bytes of the stretch (`BYTES_PER_STEP`): a literal (the bytes
     it compares; a case-insensitive one, four bytes per character), a delegate to the linear
     engine and `(?~…)` (what they matched), a look-behind of variable length (what it matched,
     once more when it fills groups, and one step per candidate start when it is a "hard" one), a
     backreference (the bytes it compares), a look-behind of fixed length (the bytes it walks
     back, whether it gets to walk all its characters or the text ends first), `\Z` (the newlines
     it skips) and the seek that finds where to start (up to the end of what it found).
   - An instruction that walks capture slots takes one more step for every 16 slots
     (`SLOTS_PER_STEP`): starting a search (it sets up every slot of the program), filling the
     groups of a delegate, and looking a slot up among those saved since the last branch (`save`
     and the exit of an atomic group, which look one by one: `State::scanned`, charged by the next
     instruction). Slots and not bytes, so that a search costs the same on every target.
   - A case-insensitive backreference takes 16 steps (`FOLD_STEPS`) for every pair of characters
     it has to fold (those that are not equal and not both ASCII); see item 7.
   - When a search needs a step and there is none: `RuntimeError::StepLimitExceeded`.
   - The searches upstream already had (`find`, `captures`, `is_match`, the iterators…) run with
     a budget nothing reaches (`u64::MAX`): their behaviour is the same as before, and
     `backtrack_limit` still applies to them.
   - A pattern without fancy features runs entirely in the linear engine and spends nothing.
     Since 0.20 that includes `\b`, `\B`, `\<` and `\>`.

   What the budget does not bound: a stretch that the linear engine reads and does **not** match
   costs only the step of its instruction, because the linear engine does not say how far it
   read. The time of a search is bounded by its steps times the length of the text, not by its
   steps alone.

   `Regex::program_len()` says how many instructions the compiled program has (0 when the whole
   pattern goes to the linear engine). A search that does not repeat work runs each instruction
   at most once per position of the text, so a caller can size a default budget from it.

2. **A size limit that counts what a search needs (`src/compile.rs`, `src/lib.rs`,
   `src/error.rs`).**
   - `RegexBuilder::program_size_limit(bytes)` (and the same on `RegexOptionsBuilder`). Without
     it, as upstream: no limit, and nothing is counted.
   - What is counted, as it is built (`VMBuilder::charge`):
     - every instruction of the program with the text or the ranges it owns (`insn_bytes`; every
       instruction is added in one place, `VMBuilder::add`);
     - the regex of each piece handed to the linear engine and the DFA (with its NFA) of each
       look-behind of variable length, where it is built: instructions with the same piece share
       one regex (upstream's `delegate_memo`), and it is counted once. For that to be what the
       program holds, they share the object (`Delegate::inner` is an `Arc`): upstream gives each
       instruction a clone, and a clone of a `meta::Regex` comes with a pool of search caches
       of its own, some 4 KB that nothing counted and that this fork does not use (item 3). A
       group with one piece, copied 8 192 times by subroutine calls (a pattern of 181 bytes),
       held 46 MB for 11 counted;
     - the search cache of each of those, with everything it will hold whatever the text is
       (`fresh_meta_cache_bytes`). A cache as `create_cache` returns it does not have the table of
       the PikeVM yet (the meta engine makes it the first time the PikeVM runs), so the cache that
       is counted is one that was made and reset (`Cache::reset` makes the table). That table is
       one row of capture slots for every state of the NFA, twice: with G groups it grows with G
       times the states. It is worked out before the cache is made, so that a regex whose table
       does not fit is an error and not an allocation: first from what the regex takes (it cannot
       have more states than that), and only when that bound does not fit, from the NFA built
       again to count its states (`nfa_states`).
   - When the whole pattern goes to the linear engine there is no program, and what is counted is
     that regex and its cache (`new_options`).
   - Over the limit it is `CompileError::ProgramTooLarge { limit, reached }`. Compiling stops at
     the first piece that does not fit, so `reached` is little more than `limit` whatever the
     whole would have taken. The size limit of each piece (`delegate_size_limit`, which
     `regex_automata` applies to its NFA) is at most the limit of the program
     (`piece_size_limit`), and a piece that goes over its own is reported as the program going
     over its (`inner_error`, `build_reverse_dfa`), not as "Error compiling regex".
   - The sizes are those of the target (a pointer is 4 bytes on wasm32), so a pattern within a
     few percent of the limit can fit on one target and not on another. The message of the error
     does not print `reached`, so it is the same everywhere.
   - The program gives back the spare capacity of the vector it was built in
     (`VMBuilder::build`): a vector that grows by doubling held up to twice what was counted.
     Measured over the families of patterns of the design (lexers, lists of words, chains of
     subroutine calls, counted repetitions), what is counted is 90 % or more of what the
     allocator holds for the compiled regex, and more than all of it when the regex has search
     caches (they are counted when compiling and made when searching).
   - What the limit does not count: the backtrack stack (it has the limit upstream gives it),
     what the caches add while they read text (item 3), and what compiling asks for and gives
     back before it ends (the linear engine builds an automaton of 14 MiB with a peak of 37).
   - `Regex::fresh_search_cache_bytes()` says what was counted for the caches.

3. **The search caches belong to the program, and their growth has a budget (`src/vm.rs`,
   `src/compile.rs`, `src/lib.rs`).**
   - Upstream keeps the cache of each piece inside that piece (a pool per regex and per DFA),
     where nothing counts what they hold. Here a program has one set of caches per thread
     (`SearchCaches`, in the scratch that upstream already pools in `Prog`), one per regex or DFA
     that searches (the number the compiler gave it: `Delegate::cache`, `Seek::cache`, the two of
     a look-behind), and every search goes through `regex_automata` with its cache
     (`search_with`, `search_half_with`, `search_slots_with`, `try_search_rev`,
     `try_search_overlapping_rev`).
   - `RegexBuilder::search_cache_limit(bytes)` (and the same on `RegexOptionsBuilder`; default: no
     limit). After every search of a piece, the cache it used is counted again
     (`Cache::memory_usage`), and what is compared with the limit is what all the caches hold
     **over what the compiler counted for each** (`CacheSet::fresh`, `SearchCaches::grown`). Over
     it, all the caches are dropped, and each is made again when its piece next searches. The
     table of the PikeVM, which is inside the size limit, is not growth when it appears: measuring
     the total made a pattern with many groups drop and rebuild its caches at every search.
   - So what the caches of a program hold at one time is what the compiler counted, the limit,
     and what the last search of one piece added (the cache of a lazy DFA has its own limit).
   - A search gives the same result and takes the same steps with a new cache; what changes is
     the time: counting a cache after every search, and making again what was dropped when a
     pattern needs to grow more than the limit.
   - `Regex::search_cache_drops()` says how many times the caches of the calling thread were
     dropped for growing over the limit; `Regex::search_cache_bytes()`, what they hold, as counted
     after the last search of each; `Regex::trim_search_caches(keep)` drops them when they hold
     more than `keep`, for a caller that keeps many regexes alive and wants a bound on what all of
     them hold between searches.
   - A regex that goes whole to the linear engine has one cache, which `regex_automata` bounds;
     `search_cache_limit` does nothing for it. The patch takes it out of the pool inside
     `meta::Regex` and into one of its own (`WrapCachePool`), so that `search_cache_bytes` and
     `trim_search_caches` cover these regexes too.
   - What `memory_usage` reports is less than what the process holds for a cache (the allocator
     adds to it). The limits are on the count.

4. **A regex that matches only the whole text (`src/lib.rs`, `src/compile.rs`).**
   - `RegexBuilder::full_match(true)` (and the same on `RegexOptionsBuilder`). Default: false.
   - The pattern is parsed as written, and its tree goes between a start-of-text and an
     end-of-text assertion. A call to the whole pattern (`\g<0>`) calls the pattern as written,
     without the two assertions (`compile` takes the second child of the root for it).
   - Why not write `^(?:` and `)$` around the text of the pattern, which is what a caller can do
     with upstream: `\g<0>` then calls the assertions too, and never matches inside the text
     (`\((?:[^()]|\g<0>)*\)` wrapped that way says that `((a)(b))` is not balanced); a pattern in
     verbose mode that ends in a comment takes the closing as part of the comment; and an
     unbalanced pattern (`a)(b`) becomes valid.
   - The tree is compiled as it is: the optimization pass does not run on it
     (`should_optimize`), because it rewrites roots, and a look-ahead at the end of the pattern
     has to stay where it can see the end of the text.
   - A pattern without fancy features still goes whole to the linear engine, with the two
     assertions.

5. **A repetition count that does not fit in 32 bits is an error (`src/parse.rs`,
   `src/error.rs`).** Upstream reads the count with `usize` and takes one that does not fit as
   "not a count": the `{` becomes a literal character. Where that happens depends on the target
   (2^64 on a 64-bit target, 2^32 on wasm32), so the same pattern meant something else in the
   WebAssembly builds. With the patch, `a{4294967296}` is `ParseError::RepeatCountTooLarge` on every
   target; the limit is the one of the `regex` crate. It is an error only when the braces close:
   `a{4294967296` without its `}` is not a repetition, and stays the literal text it is upstream
   (like `a{2`).

6. **Where a group starts is decided when compiling (`src/compile.rs`, `src/vm.rs`,
   `src/lib.rs`).**
   - Upstream decides while it runs whether entering a group saves its start: it does not when
     the group has an end ahead of the position, taking that to mean "this group is open and
     being called from inside". The same is true when a look-ahead or a call enters the group
     further back than its last match, and then the group comes out with the start of one match
     and the end of another. In 0.20.2: `(\((?:[^()]|\g<1>)*\))` on `((a)(b))` gives `(b))` for
     group 1, `(a(?:\g<1>)*b)` on `aababbab` gives `abb`, and `(?=b\g<1>)((?=))` on `b` gives a
     start after the end, which panics in `Match::as_str`.
   - With the patch the compiler knows it: it keeps the groups it is compiling the content of
     (`Compiler::open_groups`: the groups as written and the copies of subroutine calls), and
     emits the instruction that saves the start only where the group is not open
     (`Compiler::compile_group`). The VM saves whenever the instruction runs.
   - Two guards, for a mistake in this model to be a missing group and not a panic:
     `Captures::get` returns `None` for a group whose start is after its end (with a
     `debug_assert!` that says so in tests), and a backreference to such a group does not match
     (upstream slices the text with it: `vm.rs:1610`, "slice index starts at 2 but ends at 1",
     reached by a pattern the fuzz found; it is a test in `backtrack.rs`).
   - What 0.18.0 needed and 0.20 does itself: a backreference written inside its group (`(a\1?)+`)
     reads what the group matched the time before, as PCRE does
     (`SaveCaptureGroupStartKeepPrevious`). The option the patch had for it
     (`reject_self_backrefs`) is gone.

7. **A case-insensitive backreference compares character by character (`src/vm.rs`).**
   - Upstream compares a stretch of the text as long in bytes as the group. Two characters that
     are equal under simple case folding can differ in length (`ẞ` takes 3 bytes and `ß` takes 2;
     the Kelvin sign takes 3 and `k` takes 1; `ſ` takes 2 and `s` takes 1), so that stretch ends
     in the middle of what the group would match, or after it: in 0.20.2 `(?i)(ẞ)\1` does not
     match `ẞß`, and `(?i)(s)\1` does not match `sſ`.
   - With the patch (`casei_backref_end`), in Unicode mode, the text is read one character for
     each character of the group, with the equivalence of a case-insensitive literal
     (`chars_fold_equal`), and the reference ends where the last of them does. It is what Perl
     and the `regex` module of Python give. Without Unicode it is the comparison of upstream.
   - When the text left is shorter than the group, upstream says "no" without looking. So does
     this unless the text has a character with a shorter equivalent (`text_can_shrink`, worked
     out once per search from the case folding tables of `regex-syntax`): a group is a piece of
     the text, so without one no group can match fewer bytes than it has. That keeps `(é+)\1`,
     which tries the reference once for every length of the group, at one comparison and not one
     per length.

8. **The optimizer can leave the repetitions as written (`src/optimize.rs`, `src/lib.rs`,
   `src/byte_set.rs`).**
   - `RegexBuilder::optimize_repeats(false)` (and the same on `RegexOptionsBuilder`; default:
     true, as upstream). The optimization pass of 0.20 does two kinds of things: it hoists `\K`
     and a positive look-ahead at the end of the pattern, so that the rest can go whole to the
     linear engine, and it rewrites repetitions (nested repeats, and two runs of the same
     expression around an optional middle). With `false` it does only the first.
   - Why: the rewrite of two runs compares them as expressions, and two capture groups with the
     same contents are the same expression. In 0.20.2, `b(a){1,3}\n??(a){2,}` on `baaa` comes out
     with three groups where the pattern has two, and the two that were written unset. A
     differential run of this version found 8 such patterns in 3 000.
   - `RegexOptions::optimize_options` builds what the pass is told in one place, for the compile
     path and for the two prefilter helpers of `byte_set.rs`, which have to look at the same tree.

9. **The analysis is linear, says the same thing every time and does not overflow
   (`src/analyze.rs`, `src/compile.rs`).**
   - The check for left recursion walked the calls from every group with a fresh set of visited
     groups: for a chain of G groups, G² visits (16 000 groups, 7.6 s). It now shares one set
     across the starting groups, and takes them in order, so the group the error names does not
     depend on the order of a hash map.
   - The minimum size of a repetition and of a conditional is added and multiplied with
     saturation (two nested counts of 2^31 overflowed `usize`: a panic in a build that checks
     overflow, and without the check a size that wraps around). So are the two sums the compiler
     makes from those sizes (`go_back` of a look-behind, `DelegateBuilder::push`), which
     overflowed with `(?:a{4294967295}){4294967295}` twice in a row.

10. **What a repetition that can match empty gives does not depend on which engine runs it
    (`src/analyze.rs`).**
    - The two engines read an iteration that matches nothing differently. It happens in a
      repetition with no upper bound whose body can match empty (`(b?)*`, `(a*)+`,
      `(?:a?|b)+`). The linear engine never follows an empty iteration: it drops that way
      through the body and goes on to the next one that reads text. The VM lets the empty
      iteration through once and leaves the loop there, as Perl and PCRE do.
    - Two things come out differently. A capture group inside, when the last iteration is the
      empty one: it ends empty in the VM, and with the last text it read in the linear engine
      (`(b?)*` on `b`). And the match itself, when the body tries an empty way before one that
      reads text (`a?|b`, `b??`, `a*|b`): `(?:a?|b)+` on `ab` is `a` in the VM (the second
      time around `a?` matches nothing, and the loop ends there) and `ab` in the linear engine
      (which goes on to `b`).
    - Which engine runs a repetition depends on what is around it, and upstream decides that
      piece by piece: `(b?)*` on `b` gave group 1 = `b` (the pattern goes whole to the linear
      engine), `(b?)*(?<!x)` gave an empty group 1 (the VM), `(?<!x)(b?)*` gave `b` again (the
      repetition is a piece the VM hands over), and so did `(b?)*(?=)` (the optimizer takes the
      look-ahead out, and the rest goes whole). Differential runs found 22 patterns in 23 000
      whose groups changed that way (audit of v0.6.60, round 5) and 14 in 30 000 whose matches
      did (round 6).
    - With the patch the analysis marks that repetition as hard, like everything else the linear
      engine cannot answer for: it runs in the VM wherever it is written, with or without a
      capture group inside, and the reading is the one of Perl, of PCRE2, of Python's `re` and
      of its `regex` module. A counted repetition (`{n,m}`) has no loop (both engines run its
      copies one after another) and a body that always reads text has no empty iteration:
      those are delegated as before.
    - What it costs: such a pattern has a program and takes steps, and it is the shape that
      backtracks exponentially (`(a*)*b`, `(?:a*)*b`): with a step budget that is an error,
      where the linear engine answered in linear time.

11. **A quantifier does not take another quantifier (`src/parse.rs`).**
    - Upstream ends a piece at its first quantifier. A `*`, `+` or `?` after it starts a piece
      with nothing to repeat, which is an error (`a**`, `a{2}*`); a counted repetition after it
      starts a piece with a literal brace: `a{2}{3}` matched `aa{3}` and not `aaaaaa`, without an
      error. Perl ("Nested quantifiers") and Python ("multiple repeat") reject it, and the
      `regex` crate reads a repetition of the repetition.
    - With the patch (`Parser::stacked_quantifier`) a count that follows a quantifier is the
      error the other three already are, `ParseError::TargetNotRepeatable`, at the brace. So is
      a `+` after a lazy quantifier (`a+?+`, which upstream reads as lazy and possessive at
      once). A brace that is not a count (`a{2}{x}`, `a{2}{3` without its `}`) stays literal
      text, and so does one with nothing before it (`{2}a`), as in Perl.
    - Not in Oniguruma mode, where quantifiers stack (`a{2}{3}` is `(?:a{2}){3}` there).
    - In verbose mode a `+` or a `?` separated from its quantifier by a space is still its
      modifier (`(?x)a+ +a` is `a++a`), as in Perl: that does not change.
    - A possessive quantifier is greedy whatever `(?U)` says, as in PCRE. Upstream swaps it like
      any other and then makes it atomic, so `(?U)a++` took the least it could and never gave
      it back: three matches of one `a` on `aaa`, and `(?U)a*+` matched nothing. Whether the
      lazy `?` was written is looked at before `(?U)` is applied, so `(?U)a+?+` is the error
      `a+?+` is.
    - Between the braces of a count a `(?#…)` comment is not skipped
      (`Parser::whitespace_in_count`): `a{(?#c)2}` is the literal text `a{2}`, as in Perl, PCRE2
      and Python, where upstream read the count `a{2}`. The whitespace and the `#` comments of
      verbose mode are skipped there as before, and a comment between the atom and the brace
      still is (`a(?#c){2}` is `a{2}`). Inside an escape (`\x(?#c)41`, `\x{…}`) upstream skips
      a comment too, and that stays as it is: there the others do not agree with each other
      (Perl reads a NUL and then `41`, Python rejects it).

12. **A count with its minimum over its maximum is an error (`src/parse.rs`, `src/error.rs`).**
    - Upstream takes `a{3,2}` (outside Oniguruma mode, whose documentation says that
      "`fancy-regex` would normally treat `x{3,0}` as a syntax error"), and each part reads it
      its own way: the linear engine as `a{3}`, the VM as `a{2}`, and the DFA of a look-behind
      does not build. So `a{3,2}` on `aaa` matched `aaa` alone and `aa` with a look-behind next
      to it. The analysis gave it the size of the larger count, so the VM compiled `(a{1,0})*`
      without the check for an empty iteration and went around on it until the step budget or
      the backtrack stack ran out, on a text of two letters.
    - With the patch it is `ParseError::RepeatCountOutOfOrder`, at the brace, as in PCRE2,
      Python and the `regex` crate. (Perl takes it and never matches.) Item 10 relies on it:
      the size the analysis gives a body is zero for every body that can match empty.
    - Not in Oniguruma mode, where the limits are swapped and the repetition is possessive.

13. **An alternation that the linear engine would try in another order runs in the VM
    (`src/analyze.rs`, `src/to_hir.rs`, `src/lib.rs`).**
    - `regex-syntax` takes out of an alternation what all its branches start with, whatever it
      is (`lift_common_prefix`: `x*a|x*b` becomes `x*(?:a|b)`). When that beginning can end in
      more than one place, the factored form tries the branches in another order: every branch
      with the first way of the beginning, before any branch with the second. `a?a|a?b` on
      `ab`: as written, the first branch matches `a` with its `a?` empty, and that is the match
      (in Perl, in Python and in the VM); factored, `a?` takes the `a` and the match is `ab`.
      `\s*\n|\s*x` on a space, a newline and an `x` matches the first two as written and the
      three once factored. (RE2 factors only a beginning of fixed size.)
    - Like the repetition of item 10, an alternation went to the linear engine or ran in the VM
      by what was around it, so its match changed with a look-behind next to it. A run of the
      probe of the audit of round 6 with more seeds found 2 such patterns in 90 000.
    - With the patch such an alternation is hard, and so is what contains it. Which ones they
      are is not worked out from the shape of the pattern: it is asked. After `analyze`,
      `analyze_for_linear` builds what the linear engine would get, with the function that
      builds it for real (`expr_to_hir`), and looks at what `Hir::alternation` gave back for
      each alternation (`reordered`, in `to_hir.rs`). A concatenation is a beginning taken out,
      and it counts when a part of that beginning can end in more than one place
      (`more_than_one_end`, which says yes unless the lengths `regex-syntax` gives its own
      tree, or the kind of the part, say otherwise). An alternation that comes back as one, or
      as a class, is as written.
    - An alternation reaches the linear engine in two ways that do not build the same thing:
      with the whole pattern, where the places of the groups of a `{0}` and of a DEFINE block
      are kept, and in a piece the VM hands over, where they are not. What is left of a `{0}`
      in the whole pattern is not always nothing (`(?:a?b?){0}` is two empty repetitions), so
      two branches can start alike in one way and not in the other. Both are built where they
      can differ (a part of the tree with a `{0}` or a block in it), and an alternation has to
      come out as written in both.
    - What a DEFINE block defines is not part of what is built (the block is nothing where it
      stands). It is looked at on its own, as the piece the VM hands over when a call to a
      definition is compiled where nothing around it is hard
      (`\g<n>|(?(DEFINE)(?<n>a?a|a?b))`). The block is not hard whatever it holds, as upstream.
    - What it costs: the parts of a pattern that have an alternation and nothing hard in them
      are translated once more when the pattern is compiled (twice more with a `{0}` or a block
      in them). A part with no alternation is not translated here. Measured with a release
      build, on patterns near the 16 KiB a pattern can have (four runs; they differ by a
      couple of milliseconds, the difference between before and now does not): an alternation
      of 2 000 words between `\b` (12 KB) takes some 3 ms more (8 to 10 ms before, 11 to 13
      now), and 60 nested levels of alternations of words (16 KB) some 5 ms more (11 to 12
      before, 15 to 17 now). Patterns of some tens of bytes with an alternation take 3 to 30
      µs more. Some shapes compile faster, because they go whole to the linear engine where
      the rule of rounds 6 and 7 sent them to the VM: 1 500 branches `k…\s+v` (14 KB) went
      from some 70 ms to between 22 and 26.
    - Rounds 6 and 7 worked it out from the shape (`factorable` and `concat_shape`, a copy of
      what `Hir::concat`, `Hir::alternation` and `Hir::repetition` do), and three times in a
      row a case turned up that the copy did not have: a count of something that matches only
      empty (round 7: `\b^(?:a|)aa|(?:\b^a|(?:\b^){2})` on `aa` matched `a` alone and `aa` with
      a look-behind after it); a `{0}` of something with no upper bound, to which the analysis
      gives a size that the syntax tree does not (round 8: the same pattern with `(?:a*){0}` in
      it); and what is left of a `{0}` in the whole pattern (found while fixing round 8:
      `(?:a?b?){0}(?:x|)xx|(?:(?:a?b?){0}x|(?:a?b?){0})` on `xx` matched `x` twice alone and
      `xx` with a look-behind). The copy also marked alternations that are not factored
      (`foo\s+bar|baz\s+qux`); those go to the linear engine now.

14. **A group that only holds a place does not move the number of the others (`src/to_hir.rs`,
    `src/lib.rs`, `src/compile.rs`).** Found while testing item 13 with DEFINE blocks (round
    8). Three defects, all of them in 0.20.2 as published and in upstream's `main` on
    2026-11-13.
    - *The groups of a DEFINE block were not counted when translating for the linear engine.*
      `expr_to_hir` gave back nothing for the block and went on numbering from where it was, so
      every group after the block, in the same piece or with the whole pattern, got the number
      of a group of the block. `(?(DEFINE)(?<d>\d))(a)\g<d>` on `a1` left group 2 unset (the
      `a` went to group 1, and the call wrote over it), and `(?(DEFINE)(?<n>a)(?<m>b))(c)` on
      `c` was a regex with one group. Now the numbers of the block are skipped (`group_count`),
      and with the whole pattern each keeps its place as the groups of a `{0}` do: an empty
      group, in the set of the groups that never take part.
    - *Two pieces with the same text share an engine, and a block wrote nothing in that text*
      (`DelegateBuilder::build_delegate` keys its engines by the text of the piece). The piece
      `(?(DEFINE)(q))(a)` took the engine of an earlier piece `(a)`, which numbers its group
      one lower: `(?:(a)x*(?(DEFINE)(q))(a))(?<!@)` on `aa` gave the last `a` to group 2. Now
      `Expr::to_str` writes the places of the groups of the block (`(?:(){0}…)`, groups that
      are never tried), which also keeps the numbers right if a piece is ever built from its
      text. A batch of only blocks is still no instruction: `compile_delegates` skips it for
      what it is, where upstream skipped it for its empty text.
    - *With an explicit group 0, the groups that never take part were looked up one number
      early.* The set has the numbers the groups have in what the linear engine was given, and
      an explicit group 0 (what the pass that hoists a final look-ahead leaves) moves every
      group one up; `get_span` looked up the number the caller asks for. `(x){0}(a)(?=b)` on
      `ab` gave `""` for group 1 and nothing for group 2.

15. **A capture group in a positive look-behind of variable size is an error
    (`src/compile.rs`, `src/error.rs`, `src/seek.rs`).** Audits of rounds 9 and 10.
    - Upstream compiles such a look-behind in three ways, by what its body has. With an easy
      body (`compile_variable_lookbehind`): a reverse DFA gives one start, and when there are
      groups a forward search of the linear engine fills them, anchored at that start and not
      at its end. With something hard in its body (`compile_hard_variable_lookbehind`): a
      reverse DFA gives every place the body could start, they are tried from the nearest to
      the farthest, and from each one the VM matches the body as written and it has to end
      where the look-behind is. And an alternation at the top is taken apart into one
      look-behind for each branch (`compile_lookaround`).
    - The three do not give the same groups. A group could end before the look-behind:
      `(?<=(a|ab))c` on `abc` gave `a`, and `(?<== (\d+|\d+\.\d+));` on `x = 3.14;` gave `3`.
      The start is not the same: `(?<=(\d+));` on `12345;` gave `12345` with an easy body and
      `5` with a branch that never matches next to it (`|(?!)\1`). And `(?<=(ab)|(b))x` on
      `abx` gave the first group, and with the alternation one level further in
      (`(?<=(?:(ab)|(b))|(?!)\1)x`), the second. What the pattern matches was the same; what
      `captures` gives was not. A probe that compares two forms of the same body found 13 to
      24 such patterns in every 1 100.
    - Engines do not agree on what such a group holds either: `java.util.regex` takes the
      nearest start (`5`), and V8 and .NET read the body from right to left (`12345`).
    - Round 9 sent every such look-behind the second way, the VM, and round 10 measured it.
      The VM runs the body forward from each start, also past the look-behind, and comes
      back: a body that can read the same text in more than one way takes exponential steps.
      `(?<=((?:\w+\s?)+))!` on `hola mundo esto es una frase larga!`, 35 characters, took 340
      steps the delegated way and 80 million in the VM, and with 29 characters it was already
      the error of the default limit. And a group that a subroutine call writes from inside
      the look-behind still depended on the way, because it is not a group of the body:
      `(?(DEFINE)(?<g>\w))(?<=\g<g>\d+)!` on `id: a12345!` gave `a` (the call is a hard child
      of fixed size in a concatenation, whose easy pieces go to a reverse DFA: the farthest
      start) and `4` with a hard child of variable size next to it (the VM: the nearest).
    - With the patch it is an error, `CompileError::LookBehindWritesGroup`, raised at the top
      of `compile_lookaround`, before any of the three ways is chosen: a positive look-behind
      that is not of one fixed size and whose body has a capture group of its own (a DEFINE
      block in it counts its groups) or a subroutine call (`writes_a_group`). The message says
      what to write: `(?:…)` if the group is only for grouping, the capture outside the
      look-behind (a group before `\K`), or a look-behind of one fixed size.
    - Not an error, and compiled as upstream compiles them: a look-behind of one fixed size
      (one start, so one thing its groups can hold), a negative one (no group of it is left)
      and one with no group and no call in it (it only has to say whether it matches).
    - *A quantifier in a seek pattern needs something to repeat* (`build_seek_pattern_impl`).
      The pattern that finds the starts of a look-behind that runs in the VM drops the wrapper
      of a capture group, and an empty group wrote nothing: for `c+(){2,}?` it was `c+{2,}?`,
      and the starts were the ones of `(?:c+){2,}?`. A negative look-behind then matched where
      a start it did not see was: `(?<!c+(){2,}?)x` matched the `x` of `cx`. Now `(?:)` is
      written where nothing was. (Round 9 found it in a positive look-behind, `(?<=c+(){2})`,
      which did not match after one `c` and is now the error above.) The same function writes
      the seek pattern of a whole regex under upstream's `seek` option, which is off by default
      and which `backtrack.rs` does not turn on; what the change does there was not measured.

16. **A conditional with two empty branches is still a conditional (`src/parse.rs`).** Audit
    of round 10. `parse_conditional` gave back the condition alone when both branches were
    empty, which is what `(?(1))` with no branches means in this crate (go on only if the
    group took part). So `(?(1)|)`, which says "nothing if it did, nothing if it did not",
    failed when group 1 had not taken part: `(?:|(a))(?(1)|)b` did not match `b`. In Perl and
    in Python's `re` it does. Now the two branches are kept. `(?(1))` with no branches is as it
    was.

Nothing else changes: no `unsafe` (upstream has none either), no new dependency.

## What a pattern matches

With every option of the patch off, twelve things differ from 0.20.2 as published:

| | 0.20.2 | this folder |
|---|---|---|
| A group entered again further back (item 6) | start of one match, end of another; a panic when they are crossed | the start and the end of the same match |
| A case-insensitive backreference whose text has another length in bytes (item 7) | does not match, or ends in another place | compares character by character |
| `a{4294967296}` (item 5) | the literal text, on a 64-bit target | an error, on every target |
| A repetition with no upper bound whose body can match empty: `(b?)*`, `(?:a?\|b)+` (item 10) | a group inside from the last iteration that read text or from the empty one, and the match as the linear engine or as the VM reads it, by where the repetition runs | the empty iteration ends the repetition, wherever it runs |
| A count or a second modifier after a quantifier: `a{2}{3}`, `a+?+` (item 11) | literal text; lazy and possessive | an error |
| `(?U)a++`; `a{(?#c)2}` (item 11) | lazy and possessive; the count `a{2}` | greedy and possessive; the literal text `a{2}` |
| `a{3,2}` (item 12) | `a{3}`, `a{2}` or an error of the DFA, by where it runs | an error |
| An alternation whose branches start alike: `a?a\|a?b` (item 13) | as written or factored, by where it runs | as written |
| A group after a DEFINE block; the groups around one under a `{0}` in a pattern that ends in a look-ahead (item 14) | the number of a group of the block; an empty text for the group under the `{0}` and nothing for the one after it | every group under its own number, and nothing for the ones that only hold a place |
| A capture group or a subroutine call in a positive look-behind of variable size: `(?<=(a\|ab))c`, `(?<=(\d+));` (item 15) | compiles; the group is filled by a search anchored only at the start a reverse DFA gives, or from the nearest start with the body ending at the look-behind, by what the body has | an error |
| A negative look-behind with an empty group under a count: `(?<!c+(){2,}?)x` on `cx` (item 15) | matches the `x`: the starts it looks for are the ones of `(?:c+){2,}?` | does not match |
| A conditional with two empty branches: `(?(1)\|)` (item 16) | the condition alone: it fails when the group did not take part | matches either way |

`backtrack.rs` turns on `full_match` (for `backtrack_matches`), `optimize_repeats(false)`,
`program_size_limit` and `search_cache_limit`, and searches with the `*_with_steps` methods.

## What is not here

`Cargo.toml` is written for this folder: the features and dependencies of the library as upstream
publishes them, without the tests, benches and examples (and their dev-dependencies: `criterion`,
`quickcheck`, `matches`, `regex`). The unit tests inside `src/` are the upstream ones and are not
run by the engine's CI (this folder is not a workspace member).

## Checks

- The upstream test suite of 0.20.2 on these sources: 758 of its 780 tests pass (377 unit tests,
  368 tests in 10 integration test files, of which the one of `leftmost_longest` has none
  without its feature, and 35 doctests). The 22 that do not pin down what the patch changes:
  - `backrefs_casei_unicode_fold_orbits` (`tests/matching.rs`), item 7: its last three
    assertions say that `(ſa)(?i:\1)` does not match `ſasab`, that `(å)(?i:\1)` does not match
    `å` followed by the Angstrom sign and that `(s)(?i:\1)` does not match `sſ`, "because the
    window is sized in bytes from the captured text". Here the three match; `backtrack.rs` has
    the six cases of that test with what each gives
    (`a_case_insensitive_backreference_ends_where_its_last_letter_does`).
  - 21 of item 15. Each compiles a positive look-behind of variable size with a capture group
    or a subroutine call in it, and here that is `CompileError::LookBehindWritesGroup`:
    - `tests/captures.rs`, 7: `non_empty_captures_inside_variable_lookbehind`,
      `empty_capture_inside_variable_lookbehind`, `named_captures_inside_variable_lookbehind`,
      `captures_both_inside_and_outside_variable_lookbehind`,
      `captures_inside_variable_lookbehind_alternation`,
      `captures_inside_variable_lookbehind_many_candidates` and
      `captures_in_variable_lookbehind_subroutine_call`. They are the tests of what such a
      group holds: the farthest start for `(?<=(a+)(b+))x`, the nearest for `(?<=(?!^)(a+)\1)x`.
    - `tests/finding.rs`, 7: `hard_variable_lookbehind`,
      `hard_variable_lookbehind_tries_all_candidates`,
      `hard_variable_lookbehind_finds_match_with_many_candidates`,
      `hard_variable_lookbehind_match_at_bol_optional_whitespace_and_asterisk`,
      `hard_variable_lookbehind_negated_class_ascii`,
      `hard_variable_lookbehind_respects_unicode_and_bytes_mode` and
      `hard_variable_lookbehind_short_circuit_hits_limit`. They read only the match; the group
      is there to be read by a backreference inside the look-behind (`(?<=(a+)\1)x`) or only
      to group (`(?<=(\G|^\s*\*?)\s*)…`, from a TextMate grammar).
    - `tests/regex_options.rs`, 1: `tiny_delegate_dfa_size_limit_with_hard_variable_lookbehind`.
    - unit tests of `compile.rs`, 6: `variable_lookbehind_with_required_feature_captures`,
      `variable_hard_lookbehind_patterns_compile`,
      `variable_hard_lookbehind_applies_dfa_size_limit`,
      `variable_hard_lookbehind_applies_nfa_size_limit`,
      `variable_hard_lookbehind_can_disable_skip_cache_capacity_check` and
      `word_boundary_inside_lookbehind_compiled_on_vm_with_backref`.

    None of the 22 is of item 16 or of the seek pattern of item 15: no upstream test has a
    conditional whose two branches are both empty, or an empty group under a count.

  To repeat it: copy the published package, replace its `src/` with this one, drop `benches/`,
  `examples/` and `criterion` from its manifest and run `cargo test --no-fail-fast`.
- `patch -p1 < synsema.patch` on the published `src/` gives these sources, byte for byte.
- Random patterns, comparing every match and every group. With the sources as they were after
  round 8 (since then: the error of item 15, which stops a pattern before any search, the seek
  pattern of the same item, and item 16):
  - each pattern against four ways of writing it that match the same and send it to the other
    engine (a look-behind that always holds before it, after it and at the start of every
    group, and an empty look-ahead at its end, which the optimizer hoists): 96 000 patterns of
    the probe of the audit of round 6 (16 seeds, 128 texts each) and 60 000 of a wider
    generator (classes, anchors, flags, letters that are not ASCII; 10 seeds, some 290 texts
    each). None differs, in the matches or in the groups. Before items 10, 12 and 13 they did:
    14 in the first 30 000 for the repetition, 2 in the next 60 000 for the alternation, and
    with counts out of order, 308 in 6 000. Some 7 in 100 of the first generator are not
    compared: they run out of the step limit of the probe.
  - the same comparison on generators of the shapes the audits found, 6 000 patterns each: an
    alternation inside another with a branch that is a count of a run of assertions (round 7;
    34 differed before the count was in item 13), and the same with `{0}` repetitions of
    something with no upper bound among them (round 8; 143 differed with the rule of round
    7). None differs.
  - the same comparison on 24 000 patterns of a generator of item 14 (DEFINE blocks with
    groups, groups under a `{0}`, calls to the definitions, alternations and a look-ahead at
    the end; 6 seeds, 64 texts each): none differs. Before item 14, 2 475 of the first 4 000
    did.
  - a regex built with `full_match` against the same pattern between `\A(?:` and `)\z`: none
    differ in 12 000 patterns of the first generator.
  - item 15 (round 10): the patterns of the first generator that have a group, each written
    as the body of a look-behind, `(?<=(?:P))`. In 12 seeds, 1 146 are the error of item 15,
    and the 49 that compile (a body of one fixed size) give at every position of every text
    what the rule written by hand gives: `\A(?:P)\z` on the stretch of that size that ends at
    the position. That probe leaves out the bodies with an anchor, a word boundary or a
    look-around, which see the text around the stretch, and the possessive and atomic ones,
    which can read past the position and not give it back. Before item 15, the same body with and without something
    hard next to it (`(?<=(?:P|(?!)\1))`) differed in 13 to 24 patterns in every 1 100.

  Run on the sources as they were after round 6, and not again since:
  - 240 000 and 180 000 patterns of the two generators (40 and 30 seeds), with no difference;
  - this folder with `optimize_repeats(false)` against itself with `optimize(false)`: none
    differ in the 23 000 patterns of the probe of the audit of round 5 (seeds 1 to 5, 62 texts
    each), where 22 differed in a group before item 10. Hoisting does not change what a
    pattern matches or captures (but see item 14: with a group under a `{0}` it changed which
    group was read, and no generator of that time had one);
  - debug builds of this folder (overflow checks, `debug_assert!`): 1 500 patterns from each of
    two seeds of each generator, and 1 500 with counts out of order: no panic.

  Against 0.20.2 as published, both with `optimize(false)` (3 000 patterns of an older
  generator, run on the patch as it was after round 5): in one the published crate leaves
  group 1 with its start after its end and panics when it is read (item 6); in two, only a
  group differs, and it is the group of item 10; 285 do not compile here with the error of item
  11. It was not run again: what differs from upstream since then is what items 10 to 16 say,
  each with its cases.

  The probes are not in the repository; they are described in the design of v0.6.60 (rounds 4
  to 8).
- The engine's own tests are in `engine/crates/synsema-stdlib/src/backtrack.rs` and
  `engine/crates/synsema-runtime/tests/it/v0660_text.rs`. One of them
  (`repetitions_are_compiled_as_written`) fails the day upstream fixes the rewrite of item 8: it
  is the reminder to look at `optimize_repeats(false)` again.
- `cargo audit` does not look at a package taken by path. The `audit` job of the CI audits
  `fancy-regex` at the version in this folder's `Cargo.toml` as published, so an advisory against
  the version this fork is based on is seen.

## Updating to a new upstream version

1. Replace `src/`, `docs/`, `LICENSE` and `AUTHORS` with the ones of the new version, and update
   the version, features and dependencies in `Cargo.toml` from the published manifest.
2. Apply the patch: `patch -p1 < synsema.patch`. Resolve what does not apply; the places are the
   VM loop (`run_with`), the instructions that read a stretch of text or search with the linear
   engine, `State::save` and `backtrack_cut`, the backreference, `new_options` and the searches
   of a wrapped regex in `lib.rs`, the builder of the program (`VMBuilder`, `compile_group`,
   `DelegateBuilder::build_delegate`, `compile`), the repetition count and the quantifier in the
   parser (`parse_repeat`, `parse_quantifier`, `optional_whitespace`), `optimize`,
   `Analyzer::visit` (the sizes and the repetition) with `check_left_recursion`, and for items
   13 to 16: `analyze_for_linear` (new, after `analyze`) and its call in `new_options`, the
   arms of `expr_to_hir` for an alternation, a `{0}` and a DEFINE block, the DEFINE arm of
   `Expr::to_str`, `compile_delegates`, `CapturesImpl::get_span`, the look-behind arm of
   `compile_lookaround` (the error of item 15, with `writes_a_group`), the repetition arm of
   `build_seek_pattern_impl`, and the end of `parse_conditional`. A new instruction that owns
   memory goes in
   `insn_bytes`; one that reads a stretch of the text pays for it with `spend(steps,
   stretch(…))`; one that searches with the linear engine gets its cache from `new_meta_cache` or
   `new_lazy_cache` when it is compiled (which is what counts it), takes it from `SearchCaches`
   and counts it with `searched_meta` or `searched_lazy`; a new way to enter a group goes through
   `compile_group`.
3. Run the upstream suite and the differential probe against the new published version, without
   its optimizer and with it. What the probe finds in the published crate decides what stays in
   the patch: items 6, 7, 8 and 10 to 16 are there for what 0.20.2 does. Item 13 is there for
   what `regex-syntax` 0.8.11 does too. It asks `regex-syntax` what it made of each
   alternation, so a version that factors in another way is followed; what has to be read
   again is `reordered`, which knows the three things `Hir::alternation` gives back today and
   takes anything else for not as written. The test
   `an_alternation_that_the_linear_engine_would_factor_matches_the_same_wherever_it_runs` of
   `backtrack.rs` says which patterns go to each engine, and
   `groups_that_only_hold_a_place_do_not_move_the_others` is the one of item 14,
   `a_capture_group_in_a_look_behind_of_variable_length_is_an_error`, the one of item 15, and
   `a_conditional_with_two_empty_branches_matches_whatever_the_condition_says`, the one of
   item 16. If upstream comes to read the groups of a look-behind of variable size in one way,
   whatever its body has, and at a cost that does not grow exponentially, the error of item 15
   can go.
4. Regenerate `synsema.patch` (`diff -ru` of the published `src/` against this one) and update
   the version, checksum and commit at the top of this file.
5. A new minor version of a 0.x crate can change what a pattern means, and here that is a change
   of the language: it goes through the design of a Synsema version, with its table of cases.
   From 0.18.0 to 0.20.2 it did: a backreference inside its group, a conditional on an open
   group, `\b` in the linear engine.

If upstream adds a way to bound work (a step or instruction limit a caller can share between
searches), the size of what it compiles and what its searches need, and fixes items 6 to 8 and
10 to 16, this fork can go: `backtrack.rs` needs only the `*_with_steps` searches, `program_len`,
`program_size_limit`, `search_cache_limit` with `trim_search_caches` (and the two counters its
tests read, `fresh_search_cache_bytes` and `search_cache_drops`), `full_match` and
`optimize_repeats`.
