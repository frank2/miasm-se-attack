# miasm-se-attack
## tl;dr before release
* miasm is a really awesome tool with a lot of awesome tools to assist in reverse engineering.
* It intentionally does not properly model the `call` instruction on x86 for its symbolic execution engine.
  * This is not technically bad, we'll explain later.
* This repository contains two functional attacks on the assumptions it currently makes:
  * Only specific call registers are modified, namely `rsp` and `rax` (samples/benign.exe)
  * Call instructions return immediately to the next instruction (samples/hostile.exe)
* Attacks are simple:
  * Employ PFUCC (Pretty Fucked Up Calling Convention)
    * all registers are volatile
    * any register can be used to input arguments
    * any register can be used to return arguments
    * multiple registers can be used at once to return values
  * Create `call` proxies which can redirect the return address from the call.
* Defense is equally simple:
  * Correctly model the `call` instruction
* To see the attacks in action, comment out the `call_effects` patch in the lifter model in the solution files.
* Hostile solution coming soon.

## Running
You need:
* Python 3
  * pefile
  * miasm

Once you have Python:
```
$ pip install pefile miasm
$ python3 solve_benign.py
```

I have no clue if this runs on Linux (since it never technically executes the program) so let me know if it does!
