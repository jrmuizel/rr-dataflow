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
            return true

    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    if i.id in (X86_INS_PUSH, X86_INS_CALL, X86_INS_JMP):
        # these instruction don't write to a register
        pass
    elif i.id in (X86_INS_POP,):
        src = i.operands[0]
        if src.type == X86_OP_REG:
            print("reg used %s \n" %i.reg_name(src.reg))
            return normalize_reg(reg) == normalize_reg(src.reg)
    elif len(i.operands) == 2:
        print("two oper")
        src = i.operands[0]
        if src.type == X86_OP_REG:
            print("reg used %s \n" %i.reg_name(src.reg)),
            return normalize_reg(reg) == normalize_reg(src.reg)
    else:
        print("unknown src")

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
        print("pc %x" % (gdb.selected_frame().pc()))
        i = getinsn()

class Origin(gdb.Command):
    def __init__(self):
        super (Origin, self).__init__("origin", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)

    def invoke(self, arg, from_tty):
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
                if src.mem.index:
                    print("index (int*)($%s + $%s*%d + %d)" % (i.reg_name(src.mem.base), i.reg_name(src.mem.index), src.mem.scale, src.mem.disp))
                    addr = gdb.parse_and_eval("(int*)($%s + $%s*%d + %d)" % (i.reg_name(src.mem.base), i.reg_name(src.mem.index), src.mem.scale, src.mem.disp))
                else:
                    addr = gdb.parse_and_eval("(int*)($%s + %d)" % (i.reg_name(src.mem.base), src.mem.disp))
                location = ("*(int*)(%s)" % (addr))
                print("mem used " + location)
                b = gdb.Breakpoint(location, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
                gdb.execute("rc")
                #XXX temporary breakpoints aren't working for some reason, so we delete manually
                # print("TEMP" + str(b.temporary))
                b.delete()
            else:
                print("unknown src type")
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
        else:
            print("unknown src")

Origin()

