
import struct

from settings import getSetting
from history import History

from unicorn import *
from unicorn.arm_const import *

from stateManager import StateManager
appState = StateManager()

class MultipleErrors(Exception):
    """
    This exception class is used to store multiple execution errors. It is useful if there
    are multiple errors in one instruction. Also, this class can be iterated to treat each error individually.
    """

    def __init__(self, error=None, info=None, line=None):
        """
        Initialize a empty class if error and info are None.
        Otherwise, initialize the class with the corresponding parameters.

        :param error: a str containing the error type
        :param info: a str containing information on the error
        :param line: the line number when the error occurs (default None)
        """
        if error and info:
            self.content = [(error, info, line)]
        else:
            self.content = []
        self.idx = 0

    def __bool__(self):
        return len(self.content) != 0

    def __iter__(self):
        return self

    def __next__(self):
        try:
            retval = self.content[self.idx]
        except IndexError:
            self.idx = 0
            raise StopIteration()
        self.idx += 1
        return retval

    def append(self, error, info, line=None):
        self.content.append((error, info, line))

    def clear(self):
        self.idx = 0
        self.content = []


class Simulator:
    """
    Main simulator class.
    None of its method should be called directly by the UI,
    everything should pass through bytecodeinterpreter class.
    """

    PC = 15  # Helpful shorthand to get a reference on PC

    def __init__(self, memorycontent, assertionTriggers, addr2line, pcInitValue=0):
        # Parameters
        self.pcoffset = 8 if getSetting("PCbehavior") == "+8" else 0
        self.PCSpecialBehavior = getSetting("PCspecialbehavior")
        self.allowSwitchModeInUserMode = getSetting("allowuserswitchmode")
        self.maxit = getSetting("runmaxit")
        self.bkptLastFetch = None
        self.deactivatedBkpts = []

        # Initialize history
        self.history = History()

        # Initialize components
        self.pcInitVal = pcInitValue

        # --- NEW UNICORN ENGINE ---
        # Initialize Unicorn Engine in ARM mode
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        
        # Map 2MB of aligned virtual memory
        self.ADDRESS = 0x10000 
        self.SIZE = 2 * 1024 * 1024 
        self.mu.mem_map(self.ADDRESS, self.SIZE)

        # Write the assembler bytecode directly into Unicorn's memory
        for addr, data in memorycontent.items():
             self.mu.mem_write(addr, bytes(data))

        # Set the initial Program Counter (PC) register
        self.mu.reg_write(UC_ARM_REG_PC, self.pcInitVal + self.pcoffset)

        # Initialize assertion structures
        self.assertionCkpts = set(assertionTriggers.keys())
        self.assertionData = assertionTriggers
        self.assertionWhenReturn = set()
        self.callStack = []
        self.addr2line = addr2line

        # Initialize execution errors buffer
        self.errorsPending = MultipleErrors()

        # Initialize interrupt structures
        self.interruptActive = False
        # Interrupt trigged at each a*(t-t0) + b cycles
        self.interruptParams = {"b": 0, "a": 0, "t0": 0, "type": "FIQ"}
        self.lastInterruptCycle = -1

        self.stepMode = None
        self.stepCondition = 0
        # Used to stop the simulator after n iterations in run mode
        self.runIteration = 0
        self.history.clear()

    def reset(self):
        """
        Reset the state of the simulator.
        Memory content is preserved, but PC is reset to its initial value.
        """
        self.history.clear()
        self.mu.reg_write(UC_ARM_REG_PC, self.pcInitVal + self.pcoffset)

    def getContext(self):
        """
        Return the current context (registers and memory) for the UI.
        """
        context = {"regs": self.getRegisters(), "mem": self.getMemoryContext()}
        return context

    def setStepCondition(self, stepMode):
        assert stepMode in ("into", "out", "forward", "run")
        self.stepMode = stepMode
        self.stepCondition = 1
        self.runIteration = self.history.cyclesCount

    def isStepDone(self):
        maxCyclesReached = self.history.cyclesCount - self.runIteration >= self.maxit
        if self.stepMode == "forward":
            if self.stepCondition == 2:
                # The instruction was a function call
                # Now the step forward becomes a step out
                self.stepMode = "out"
                self.stepCondition = 1
                return False
            else:
                return True
        if self.stepMode == "out":
            return self.stepCondition == 0 or maxCyclesReached
        if self.stepMode == "run":
            return maxCyclesReached

        # We are doing a step into, we always stop
        return True

    def loop(self):
        """
        Loop until the stopping criterion is met.
        """
        self.history.setCheckpoint()
        
        # Execute at least one instruction
        self.nextInstr()  
        
        # Repeat until the UI stopping criterion is met
        while not self.isStepDone():  
            self.nextInstr()
    
    def stepBack(self, count=1):
        for c in range(count):
            self.history.stepBack()
        self.fetchAndDecode(forceExplain=True)
        self.bkptLastFetch = None

    def executionStats(self):
        """
        Return a dictionary with the number of times each instruction type was executed
        in the last execution run.
        The types are:
        - "data" (includes all arithmetic and logic operations except multiply)
        - "mem" (includes all _single_ memory accesses including byte, half or word access and swap)
        - "multiplemem" (all _multiple_ memory accesses: LDM, STM, POP, and PUSH)
        - "branch" (all branches, B/BL/BX alike)
        - "multiply" (multiply and multiply long operations)
        - "softinterrupt" (self explanatory)
        - "psr" (CPSR/SPRS <-> register transfers)
        - "nop" (NOP instructions)

        These keys are associated to a 2-integers tuple. The first value is the number of times
        this kind of instruction was executed, the second the number of times if _would_ have been
        executed except for the condition field (e.g. the condition was not met).
        """
        memExec = self.decoders["MemOp"].execCounters
        halfMemExec = self.decoders["HalfSignedMemOp"].execCounters
        swapExec = self.decoders["SwapOp"].execCounters
        multiplyExec = self.decoders["MulOp"].execCounters
        multiplyLongExec = self.decoders["MulLongOp"].execCounters

        return {
            "data": self.decoders["DataOp"].execCounters,
            "mem": (
                memExec[0] + halfMemExec[0] + swapExec[0],
                memExec[1] + halfMemExec[1] + swapExec[1],
            ),
            "multiplemem": self.decoders["MultipleMemOp"].execCounters,
            "branch": self.decoders["BranchOp"].execCounters,
            "multiply": (
                multiplyExec[0] + multiplyLongExec[0],
                multiplyExec[1] + multiplyLongExec[1],
            ),
            "softinterrupt": self.decoders["SoftInterruptOp"].execCounters,
            "psr": self.decoders["PSROp"].execCounters,
            "nop": self.decoders["NopOp"].execCounters,
        }

    def fetchAndDecode(self, forceExplain=False):
        # Fetch and decode are handled natively by Unicorn Engine
        pass

    def explainInstruction(self):
        # Stub for UI compatibility
        self.disassemblyInfo = (
            ["highlightRead", []],
            ["highlightWrite", []],
            ["nextline", None],
            ["disassembly", '<div id="disassembly_instruction">Executing via Unicorn Engine...</div>\n'],
        )

    def execAssert(self, assertionsList, mode):
        for assertionInfo in assertionsList:
            assertionType = assertionInfo[0]
            if assertionType != mode:
                continue
            assertionLine = assertionInfo[1]
            assertionInfo = assertionInfo[2].split(",")

            strError = ""
            try:
                for info in assertionInfo:
                    info = info.strip()
                    if "=" not in info:
                        # Bad syntax, we skip
                        continue
                    target, value = info.upper().split("=")

                    # The rest of the code assume that a register is encoded
                    # as R**, so we convert the alternative names
                    if value.strip() in ("SP", "LR", "PC"):
                        value = {"SP": "R13", "LR": "R14", "PC": "R15"}[value]
                    if target.strip() in ("SP", "LR", "PC"):
                        target = {"SP": "R13", "LR": "R14", "PC": "R15"}[target]

                    if value.strip()[0] == "R":
                        # The target is another register
                        regtarget = int(value[1:].strip())
                        self.regs.deactivateBreakpoints()
                        val = self.regs[regtarget]
                        self.regs.reactivateBreakpoints()
                    else:
                        # The target is a constant
                        regtarget = None
                        try:
                            val = int(value, base=0) & 0xFFFFFFFF
                        except ValueError:
                            # If this is a decimal with leading zeros, base=0 will crash
                            val = int(value, base=10) & 0xFFFFFFFF

                    if target[0] == "R":
                        # Register
                        reg = int(target[1:])

                        self.regs.deactivateBreakpoints()
                        valreg = self.regs[reg]
                        self.regs.reactivateBreakpoints()
                        if valreg != val:
                            if regtarget:
                                strError += appState.getT(3).format(
                                    target, val, regtarget, valreg
                                )
                            else:
                                strError += appState.getT(4).format(
                                    target, val, valreg
                                )
                    elif target[:2] == "0X":
                        # Memory
                        addr = int(target, base=16)

                        formatStruct = "<B"
                        if not 0 <= int(val) < 255:
                            val &= 0xFFFFFFFF
                            formatStruct = "<I"
                        valmem = self.mem.get(
                            addr,
                            mayTriggerBkpt=False,
                            size=4 if formatStruct == "<I" else 1,
                        )
                        valmem = struct.unpack(formatStruct, valmem)[0]
                        if valmem != val:
                            if regtarget:
                                strError += appState.getT(5).format(
                                    target, val, regtarget, valmem
                                )
                            else:
                                strError += appState.getT(6).format(
                                    target, val, valmem
                                )
                    elif len(target) == 1 and target in self.regs.flag2index:
                        # Flag
                        expectedVal = value != "0"
                        actualVal = self.regs.__getattribute__(target)
                        if actualVal != expectedVal:
                            strError += appState.getT(7).format(
                                target, expectedVal, actualVal
                            )
                    else:
                        # Assert type unknown
                        strError += appState.getT(8).format(
                            target, value
                        )

                if len(strError) > 0:
                    self.errorsPending.append("assert", strError, assertionLine)

            except ComponentException as ex:
                self.errorsPending.append(ex.cmp, ex.text, assertionLine)

    def nextInstr(self, forceExplain=False):
        """
        Execute a single instruction using Unicorn Engine.
        """
        self.errorsPending.clear()
        self.history.newCycle()

        # Get the current Program Counter
        current_pc = self.mu.reg_read(UC_ARM_REG_PC)

        try:
            # Emulate exactly 1 instruction starting from current_pc
            # emu_start(start_address, end_address, timeout, count)
            self.mu.emu_start(current_pc, 0, count=1)
        except UcError as e:
            self.errorsPending.append("execution", str(e), self.getCurrentLine())
            raise self.errorsPending

    def deactivateAllBreakpoints(self):
        pass # This method is a placeholder for deactivating breakpoints, implementation depends on the rest of the codebase
    def reactivateAllBreakpoints(self):
        pass  # This method is a placeholder for reactivating breakpoints, implementation depends on the rest of the codebase

    def getCurrentLine(self):
        """
        Get the current line number corresponding to the execution PC.
        """
        # Read the current Program Counter directly from Unicorn
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        
        # Adjust PC behavior according to settings
        pc -= 8 if getSetting("PCbehavior") == "+8" else 0
        
        # Map the memory address back to the source code line number
        if pc in self.addr2line and len(self.addr2line[pc]) > 0:
            return self.addr2line[pc][-1]
        else:
            return None

    def _toggleBreakpoint(self, bkptException):
        pass  # This method is a placeholder for toggling breakpoints, implementation depends on the rest of the codebase

    def getRegisters(self):
        """
        Read all User bank registers (R0-R15) directly from Unicorn Engine.
        Returns a dictionary compatible with the old UI format.
        """
        return {
            "User": [
                self.mu.reg_read(UC_ARM_REG_R0),
                self.mu.reg_read(UC_ARM_REG_R1),
                self.mu.reg_read(UC_ARM_REG_R2),
                self.mu.reg_read(UC_ARM_REG_R3),
                self.mu.reg_read(UC_ARM_REG_R4),
                self.mu.reg_read(UC_ARM_REG_R5),
                self.mu.reg_read(UC_ARM_REG_R6),
                self.mu.reg_read(UC_ARM_REG_R7),
                self.mu.reg_read(UC_ARM_REG_R8),
                self.mu.reg_read(UC_ARM_REG_R9),
                self.mu.reg_read(UC_ARM_REG_R10),
                self.mu.reg_read(UC_ARM_REG_R11),
                self.mu.reg_read(UC_ARM_REG_R12),
                self.mu.reg_read(UC_ARM_REG_SP), # R13
                self.mu.reg_read(UC_ARM_REG_LR), # R14
                self.mu.reg_read(UC_ARM_REG_PC)  # R15
            ]
        }

    def getMemoryContext(self):
        """
        Read the simulated memory directly from Unicorn Engine.
        Formats the output as a dictionary of sections to maintain UI compatibility.
        """
        try:
            # Read 1024 bytes (1KB) starting from our mapped ADDRESS
            # You might need to adjust the size depending on UI expectations
            raw_memory = self.mu.mem_read(self.ADDRESS, 1024)

            # The old UI expects a dictionary where keys are section names
            # and values are bytearrays. We create a single 'CODE' section for now.
            return {"CODE": bytearray(raw_memory)}
        except UcError as e:
            # Return empty memory if reading fails
            return {"CODE": bytearray()}