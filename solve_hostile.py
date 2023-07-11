#!/usr/bin/env python3

import os
import sys

from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.ir.ir import AssignBlock
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprLoc
from miasm.arch.x86.sem import call as sem_call
from miasm.core.asmblock import AsmCFG

import pefile

# patch the lifter call_effects function so that it properly annotates our calls when lifting
def call_effects(lifter, ad, instr):
    assigns, aux = sem_call(lifter, instr, ad)
    return [AssignBlock(assigns)], []

def disassemble(engine, address):
    queue = list()
    visited = set()
    cfg = AsmCFG(engine.loc_db)

    queue.append(address)

    while len(queue) > 0:
        address = queue[0]
        del queue[0]
        
        new_cfg = engine.dis_multiblock(address)
        visited.add(address)

        for block in new_cfg.blocks:
            cfg.add_block(block)

            # the only instructions we really care about are blocks that end with a call instruction
            if not block.lines[-1].name == 'CALL':
                continue
            
            call_instr = block.lines[-1]

            # check for the PUSH/PUSH pattern preceeding the call to get our new locations to branch to
            if block.lines[-2].name == 'PUSH' and block.lines[-3].name == 'PUSH':
                target_function = block.lines[-2].args[0]
                return_address = block.lines[-3].args[0]

                # checking for ExprInt conveniently skips ExprMem objects, which we can really only resolve at runtime
                if isinstance(target_function, ExprInt) and not int(target_function) in visited:
                    queue.append(int(target_function))

                if isinstance(return_address, ExprInt) and not int(return_address) in visited:
                    queue.append(int(return_address))

            # call address is a known location
            if isinstance(call_instr.args[0], ExprLoc):
                offset = cfg.loc_db.get_location_offset(call_instr.args[0].loc_key)

                if not offset in visited:
                    queue.append(offset)
            # call address is an unknown location
            elif isinstance(call_instr.args[0],ExprInt) and not int(call_instr.args[0]) in visited:
                queue.append(int(call_instr.args[0]))
            
    return cfg

if __name__ == '__main__':
    #target = 'hostile'
    binary = 'samples/hostile.exe'

    print('loading PE file...')
    pe = pefile.PE(binary)
    pe_memory = pe.get_memory_mapped_image()
    pe_base = pe.OPTIONAL_HEADER.ImageBase
    
    locations = LocationDB()
    container = Container.from_stream(open(binary, 'rb'), locations)
    machine = Machine('x86_64')

    print('disassembling program...')
    engine = machine.dis_engine(container.bin_stream, loc_db=locations, dontdis_retcall=True)
    blocks = disassemble(engine, container.entry_point)

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

    if not isinstance(rip, ExprInt) or not int(rip) == 0x4054: # puts call, which is unresolved at runtime and thus resolves to this magic value
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
