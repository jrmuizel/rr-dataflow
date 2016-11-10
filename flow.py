# test1.py
import gdb

from capstone import *
from capstone.x86 import *
subregs = { X86_REG_AL: X86_REG_RAX,
            X86_REG_AH: X86_REG_RAX,
            X86_REG_AX: X86_REG_RAX,
            X86_REG_EAX: X86_REG_RAX,
            X86_REG_BL: X86_REG_RBX,
            X86_REG_BH: X86_REG_RBX,
            X86_REG_BX: X86_REG_RBX,
            X86_REG_EBX: X86_REG_RBX,
            X86_REG_CL: X86_REG_RCX,
            X86_REG_CH: X86_REG_RCX,
            X86_REG_CX: X86_REG_RCX,
            X86_REG_ECX: X86_REG_RCX,
            X86_REG_DL: X86_REG_RDX,
            X86_REG_DH: X86_REG_RDX,
            X86_REG_DX: X86_REG_RDX,
            X86_REG_EDX: X86_REG_RDX,
            X86_REG_EBP: X86_REG_RBP,
            X86_REG_EDI: X86_REG_RDI,
            X86_REG_DI:  X86_REG_RDI,
            X86_REG_DIL: X86_REG_RDI,
            X86_REG_ESI: X86_REG_RSI,
            X86_REG_SI:  X86_REG_RSI,
            X86_REG_SIL: X86_REG_RSI,
            X86_REG_SP:  X86_REG_RSP,
            X86_REG_SPL: X86_REG_RSP,
            X86_REG_BP:  X86_REG_RBP,
            X86_REG_BPL: X86_REG_RBP }

def debug(string):
    #print(string)
    pass

def normalize_reg(reg):
    if reg in subregs:
        reg = subregs[reg]
    return reg

def ismov(i):
    if i.id in (X86_INS_MOV,):
        return True
    print("not move %s" % i.mnemonic)
    return False


def isregdest(i, reg):
    # check for implicit writes
    for r in i.regs_write:
        if normalize_reg(reg) == normalize_reg(r):
            return True
    for o in i.operands:
        if o.type == X86_OP_REG and (o.access & CS_AC_WRITE):
            if normalize_reg(reg) == normalize_reg(o.reg):
                return True
        elif o.type == X86_OP_IMM:
            # immediate operands are not registers
            pass
        elif o.type == X86_OP_MEM:
            # memory operands don't write to registers
            pass
        else:
            print("unknown src")

def ismemwrite(i):
    print(i.operands)
    for o in i.operands:
        print(o)
        print(o.type, o.access)
        if o.type == X86_OP_MEM and (o.access & CS_AC_WRITE):
            return True
    if i.id == X86_INS_PUSH:
        return True

def eval_mem_operand(i, o):
    if o.mem.index:
        addr = gdb.parse_and_eval("(int*)($%s + $%s*%d + %d)" % (i.reg_name(o.mem.base), i.reg_name(o.mem.index), o.mem.scale, src.mem.disp))
    else:
        addr = gdb.parse_and_eval("(int*)($%s + %d)" % (i.reg_name(o.mem.base), o.mem.disp))
    return addr


def memaddress(i):
    for o in i.operands:
        if o.type == X86_OP_MEM:
            return eval_mem_operand(i, o)
    if i.id == X86_INS_PUSH:
        assert(False)
        #XXX this needs testing
        return gdb.parse_and_eval("(int*)($sp)")
    assert(False)

def getinsn():
    length = gdb.selected_frame().architecture().disassemble(gdb.selected_frame().pc())[0]['length']
    CODE = gdb.selected_inferior().read_memory(gdb.selected_frame().pc(), length).tobytes()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(CODE, 0x1000))
    assert(len(insns) == 1)
    return insns[0]

def step_and_watch_register(target):
    gdb.execute('rsi')
    i = getinsn()
    while not isregdest(i, target):
        # single step by instruction backwards until we find an instruction
        # that has target as a destination register
        gdb.execute('rsi')
        i = getinsn()

offset = 0
class Origin(gdb.Command):
    def __init__(self):
        super (Origin, self).__init__("origin", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)

    def invoke(self, arg, from_tty):
        global offset
        follow = (arg == "-f")
        while True:
            i = getinsn()
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if len(i.operands) == 2:
                ismov(i)
                src = i.operands[1]
                # XXX we want to check if we also use the dest register so
                # that we know if the src is ambiguous
                print(src.type)
                if src.type == X86_OP_REG:
                    print("watching %s \n" %i.reg_name(src.reg)),
                    step_and_watch_register(src.reg)
                elif src.type == X86_OP_MEM:
                    addr = eval_mem_operand(i, src)
                    if offset > 0:
                        print("adjusting", offset)
                    addr = int(addr) + offset
                    location = ("*(int*)(0x%x)" % (addr))
                    print("mem used " + location)

                    # Write watchpoints only trigger if the value has changed
                    # but we want to follow all writes so use an WP_ACCESS
                    # watchpoint and manually check if we have a write
                    class MyBreakpoint(gdb.Breakpoint):
                        def stop(self):
                            i = getinsn()
                            actual_addr = memaddress(i)
                            global offset
                            offset = int(addr) - int(actual_addr)
                            print(actual_addr, "0x%x" % (addr) , "offset", offset)
                            print(gdb.selected_frame().pc())
                            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                            if ismemwrite(i): #XXX: is memwrite is sometimes broken
                                print ("is mem write")
                                return True
                            else:
                                print ("is not mem write")
                                return True

                    b = MyBreakpoint(location, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
                    gdb.execute("rc")
                    #XXX temporary breakpoints aren't working for some reason, so we delete manually
                    # print("TEMP" + str(b.temporary))
                    b.delete()
                else:
                    print("unknown src type")
                    follow = False
            elif len(i.operands) == 1 and i.id == X86_INS_POP:
                    addr = gdb.parse_and_eval("(int*)($sp)")
                    location = ("*(int*)(%s)" % (addr))
                    print("mem used " + location)
                    b = gdb.Breakpoint(location, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
                    gdb.execute("rc")
                    #XXX temporary breakpoints aren't working for some reason, so we delete manually
                    # print("TEMP" + str(b.temporary))
                    b.delete()
            elif len(i.operands) == 1 and i.id == X86_INS_PUSH:
                    src = i.operands[0]
                    print(src.type)
                    if src.type == X86_OP_REG:
                        print("watching %s \n" %i.reg_name(src.reg)),
                        step_and_watch_register(src.reg)
                    else:
                        print("unknown src")
                        follow = False
            else:
                print("unknown src")
                follow = False
            if not follow:
                break

Origin()

