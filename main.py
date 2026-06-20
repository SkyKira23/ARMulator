import argparse
import time

from assembler import parse as ASMparser
from bytecodeinterpreter import BCInterpreter

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ARMulator")
    parser.add_argument('inputfile', help="Assembler file")
    args = parser.parse_args()

    with open(args.inputfile) as f:
        bytecode, bcinfos, line2addr, assertions, _, errors = ASMparser(f)
    print("Parsed source code!")

    a = time.time()
    interpreter = BCInterpreter(bytecode, bcinfos, assertions)
    
    with open(args.inputfile) as f:
        lines = f.readlines()
        
        # --- PRIMO PASSO ---
        interpreter.step(stepMode="forward")
        print("Cycle {}".format(interpreter.getCycleCount()))
        current_line = interpreter.getCurrentLine()
        
        if current_line is not None:
            print("Next line to execute: " + lines[current_line][:-1])
            
            # --- SECONDO PASSO (avviene solo se non abbiamo finito) ---
            interpreter.step(stepMode="into")
            print("Cycle {}".format(interpreter.getCycleCount()))
            current_line = interpreter.getCurrentLine()
            
            if current_line is not None:
                print("Next line to execute : " + lines[current_line][:-1])

        # --- ESECUZIONE DEL RESTO DEL CODICE ---
        interpreter.execute(mode="run")
        print("Cycle {}".format(interpreter.getCycleCount()))
        print("Final registers values:")
        print(interpreter.getRegisters())
        
    deltaTime = time.time() - a
    cycles = interpreter.getCycleCount()
									 
																											
    
    # Previene l'errore di divisione per zero se l'esecuzione Ã¨ quasi istantanea
    cyclesPerSec = (cycles / deltaTime) if deltaTime > 0 else 0
    
    print("Time to execute {} instructions : {:.5f} ({:.0f} instr/sec)".format(cycles, deltaTime, cyclesPerSec))