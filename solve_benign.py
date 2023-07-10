#!/usr/bin/env python3

import os
import sys

from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.ir.ir import AssignBlock
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprId, ExprInt, ExprMem
from miasm.arch.x86.sem import call as sem_call

import pefile

# patch the lifter call_effects function so that it properly annotates our calls when lifting
def call_effects(lifter, ad, instr):
    assigns, aux = sem_call(lifter, instr, ad)
    return [AssignBlock(assigns)], []

if __name__ == '__main__':
    #target = 'benign'
    binary = 'samples/benign.exe'

    print('loading PE file...')
    pe = pefile.PE(binary)
    pe_memory = pe.get_memory_mapped_image()
    pe_base = pe.OPTIONAL_HEADER.ImageBase
    
    locations = LocationDB()
    container = Container.from_stream(open(binary, 'rb'), locations)
    machine = Machine('x86_64')

    print('disassembling program...')
    engine = machine.dis_engine(container.bin_stream, loc_db=locations, follow_call=True)
    blocks = engine.dis_multiblock(container.entry_point)

    print('converting program to intermediate representation...')
    lifter_model = machine.lifter_model_call(locations)
    lifter_model.call_effects = call_effects.__get__(lifter_model, lifter_model.__class__)
    ircfg = lifter_model.new_ircfg_from_asmcfg(blocks)
    symbolic = SymbolicExecutionEngine(lifter_model)

    # set some registers so the symbolic execution engine can properly solve some things
    print('modelling execution...')
    symbolic.symbols[ExprId('df', 1)] = ExprInt(0, 1)
    symbolic.symbols[ExprId('RSP', 64)] = ExprInt(0x200000, 64)
    
    # model the memory of the executable so it can resolve memory variables
    for iter_base in range(pe_base,pe_base+len(pe_memory)):
        symbolic.symbols[ExprMem(ExprInt(iter_base, 64), 8)] = ExprInt(pe_memory[iter_base - pe_base], 8)
        
    print('solving...')
    next_addr = symbolic.run_at(ircfg, container.entry_point)
    rip = symbolic.symbols[ExprId('RIP', 64)]

    if not isinstance(rip, ExprInt) or not int(rip) == 0x3054: # puts call, which is unresolved at runtime and thus resolves to this magic value
        print('execution did not resolve')
        sys.exit(1)

    rcx = symbolic.symbols[ExprId('RCX', 64)]
    string_data = list()
    offset = 0

    while True:
        address = int(rcx)+offset
        memory = ExprMem(ExprInt(address, 64), 8)
        symbol = symbolic.symbols[memory]
        
        if int(symbol) == 0:
            break
        else:
            string_data.append(chr(int(symbol)))
            
        offset += 1

    print('solution: {}'.format(''.join(string_data)))
