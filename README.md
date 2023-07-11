# A functional attack on miasm's default symbolic execution engine configuration
## Contents

* [Introduction](#introduction)
* [Attack](#attack)
  * [PFUCC](#pfucc)
  * [Call proxies](#call-proxies)
* [Solving](#solving)
  * [Patching the lifter](#patching-the-lifter)
  * [Writing a custom disassembler](#writing-a-custom-disassembler)
* [Running the solutions](#running-the-solutions)
* [Conclusions](#conclusions)

### Introduction

[miasm](https://github.com/cea-sec/miasm) is a reverse-engineering tool with rich functionality, in particular its
symbolic execution engine. [Symbolic execution](https://en.wikipedia.org/wiki/Symbolic_execution) is a means of converting
program code into complex algebraic expressions for analysis of calculated state. By default, miasm's symbolic execution
engine models `call` instructions on x86-64 architectures in a naive way. Namely, when determining the side effects of a 
`call` instruction, it determines the following:

* The stack register was modified
* The return register (`RAX`) was modified
* The return address is the instruction following the call

All things considered, these are the basics of what you would expect a `call` instruction to do. However, the modeling of the call's
side effects are technically wrong, producing unexpected results when conducting symbolic execution on a function which calls other functions.
This is not a big deal if your `call` instruction does not effect the state of the calculation that much. However, in the face of some obfuscation
techniques, it matters a lot to follow the state of a `call` to calculate the rest of the state of the functionality
(see VMProtect's `VMEnter` function).

With that in mind, this repository contains attacks (and solutions to) on miasm's default approach to symbolic execution.

### Attack

The idea was to create a binary which could theoretically be solved fully with symbolic execution just fine, save for the two attacks that are being
performed. A custom RC4 encryption solution was created with a custom allocation function that could be trivially solved by the engine. There are two
separate attack files included in this repository, both taking advantage of two techniques:

* **benign**: A sample with no control-flow obfuscation, but non-conventional calling conventions on call instructions.
* **hostile**: A sample which contains both control-flow obfuscation and non-conventional calling conventions.

#### PFUCC

*PFUCC* (or Pretty Fucked Up Calling Convention) is a calling convention which dictates the following:

* all registers are volatile
* all registers can be function arguments
* all registers can be used to return values
* multiple registers can be used to return values

For example, one function takes `rsi`, `rdi` and `rdx` as arguments, then returns `rdi`, `rdx` and `r12` as values, and never modifies the stack.
As a result, miasm will incorrectly calculate the state of this function, since none of those registers are considered modified by the default model
of `call` instructions.

#### Call proxies

A *call proxy* is a method of obfuscating call instructions by taking advantage of its underlying functionality. A call instruction can be reduced
to the following commands:

* `push` the next instruction's address onto the stack
* `jmp` to the called address

We can take advantage of this functionality by hijacking the implicit `push` call and entirely rerouting where the called function eventually lands.
For example, consider the following assembly code:

```asm
    push return_branch
    push target_function
    call proxy
    
hostile_branch:
    mov rax, 1
    
return_branch:
    ret

proxy:
    pop rax
    pop rax
    jmp rax
    
target_function:
    xor rax, rax
    ret
```

First, the initial return address is discarded from the stack when `proxy` is called. Next, a new address is taken from the stack and jumped to.
Because an additional address was pushed to the stack when calling the proxy, this address now takes the slot originally taken by our exectuion
of the `call` instruction. `target_function` gets called as normal with the return address being `return_branch`. Without modifications, miasm's
symbolic execution engine will calculate `rax` as 1 on return, where in reality, the function returns 0. We can weaponize this technique further
by adding junk data after the call instruction, causing disassemblers to fail (e.g., view `samples/hostile.exe` in your disassembler of choice).

### Solving

There are two additional techniques one must employ to get miasm's symbolic execution engine to properly solve these samples.

#### Patching the lifter

In the lifter function for miasm there is a function which specifically returns the side-effects of a `call` instruction. This can be patched to
output the proper semantics of the `call` instruction, thus producing valid IR instructions to execute. See 
[the benign solution](https://github.com/frank2/miasm-se-attack/blob/362d2755b6b3041d4a9941e373185c4c8bd164fa/solve_benign.py#L17) for how simple this
patch was.

#### Writing a custom disassembler

The solution for the `call` proxies is not as straightforward as the solution for PFUCC, but is fundamentally just as simple. A custom disassembler
must be created in order to disassemble the code blocks. Combined with the patch to how `call` instructions are represented at the IR level, the problem
solves just fine with miasm. See 
[the hostile solution](https://github.com/frank2/miasm-se-attack/blob/362d2755b6b3041d4a9941e373185c4c8bd164fa/solve_hostile.py#L22) for how to write
a custom disassembler for miasm.

### Running the solutions

You will need:
* Python 3
  * pefile
  * miasm

Once you have Python:
```
$ pip install pefile miasm
$ python3 solve_benign.py
$ python3 solve_hostile.py
```

### Conclusions

As you can see by running the solution files, this is not a viable attack on symbolic execution, per se, but does effectively attack the default assumptions
of miasm's engine specifically. Without patches to the lifter itself, miasm's symbolic execution engine is no match for simple modifications to call
instructions (PFUCC) or intentional muckery with call instructions (call proxies). However, just as easily as the attacks are introduced, the attacks are
easily defeated with just a little bit of help to give miasm's symbolic execution engine.
