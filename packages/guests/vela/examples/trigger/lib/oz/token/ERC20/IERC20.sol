// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The ERC-20 interface, as OpenZeppelin publishes it — only what `AbstractTrigger` imports.
// Remapped from `@openzeppelin/contracts/token/ERC20/IERC20.sol` in foundry.toml so the trigger
// compiles without installing the whole library.
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
