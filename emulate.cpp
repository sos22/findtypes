/* Simple interface to VEX for doing isntruction emulation */
#include <sys/ptrace.h>
#include <sys/user.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>

#include <libVEX/libvex.h>
#include <libVEX/libvex_bb_to_IR.h>
#include <libVEX/libvex_emwarn.h>
#include <libVEX/libvex_guest_amd64.h>
#include <libVEX/libvex_guest_offsets.h>
#include <libVEX/libvex_amd64.h>

#undef offsetof
extern "C" {
#include "ft.h"
};

static Bool
resteerOkFn(void *ignore, Addr64 ignore2)
{
	return False;
}

struct expression_result {
	unsigned long lo;
	unsigned long hi;
};

struct augmented_regs {
	struct user_regs_struct urs;
	unsigned long cc_op;
	unsigned long cc_dep1;
	unsigned long cc_dep2;
	unsigned long cc_ndep;
};

static int
libvex_offset_to_linux_offset(int offset)
{
	switch (offset) {
#define reg(vex_name, linux_name)					\
	  case OFFSET_amd64_ ## vex_name ...				\
	    (OFFSET_amd64_ ## vex_name + 7):				\
			return offsetof(struct user_regs_struct,	\
					linux_name) + (offset & 7)
		reg(RAX, rax);
		reg(RBX, rbx);
		reg(RCX, rcx);
		reg(RDX, rdx);
		reg(RSP, rsp);
		reg(RBP, rbp);
		reg(RSI, rsi);
		reg(RDI, rdi);
		reg(R8, r8);
		reg(R9, r9);
		reg(R10, r10);
		reg(R11, r11);
		reg(R12, r12);
		reg(R13, r13);
		reg(R14, r14);
		reg(R15, r15);
#undef reg
	case 128:
		return offsetof(struct augmented_regs, cc_op);
	case 136:
		return offsetof(struct augmented_regs, cc_dep1);
	case 144:
		return offsetof(struct augmented_regs, cc_dep2);
	case 152:
		return offsetof(struct augmented_regs, cc_ndep);
	default:
		abort();
	}
}

static void
handle_put(struct augmented_regs *urs,
	   int offset,
	   const struct expression_result &data,
	   int size)
{
	memcpy((void *)((unsigned long)urs + libvex_offset_to_linux_offset(offset)),
	       &data,
	       size);
}

static struct expression_result
eval_expression(struct thread *thr,
		const struct augmented_regs *urs,
		IRExpr *e,
		const struct expression_result *tmp)
{
	struct expression_result res;
	memset(&res, 0, sizeof(res));
	switch (e->tag) {
	case Iex_Get: {
		if (e->Iex.Get.offset >= 192 && e->Iex.Get.offset < 552) {
			struct user_fpregs_struct fprs;
			ptrace(PTRACE_GETFPREGS, thr->pid, NULL, &fprs);
			if (e->Iex.Get.offset >= 200 && e->Iex.Get.offset < 456)
				memcpy(&res,
				       (void *)((unsigned long)fprs.xmm_space + e->Iex.Get.offset - 200),
				       sizeofIRType(e->Iex.Get.ty));
			else
				abort();
		} else {
			unsigned o = libvex_offset_to_linux_offset(e->Iex.Get.offset);
			memcpy(&res, (void *)((unsigned long)urs + o), sizeofIRType(e->Iex.Get.ty));
		}
		return res;
	}
	case Iex_RdTmp:
		return tmp[e->Iex.RdTmp.tmp];
	case Iex_Binop: {
		struct expression_result arg1, arg2;
		IRType t1, t2, t3, t4, t5;
		arg1 = eval_expression(thr, urs, e->Iex.Binop.arg1, tmp);
		arg2 = eval_expression(thr, urs, e->Iex.Binop.arg2, tmp);
		switch (e->Iex.Binop.op) {
#define simple_op(name, op)					\
		case Iop_ ## name ## 8:			        \
		case Iop_ ## name ## 16:			\
		case Iop_ ## name ## 32:			\
		case Iop_ ## name ## 64:			\
			res.lo = arg1.lo op arg2.lo;	        \
			break;
		simple_op(Add, +)
		simple_op(Sub, -)
		simple_op(Shl, <<)
		simple_op(CmpEQ, ==)
#undef simple_op
		default:
			abort();
		}
		typeOfPrimop(e->Iex.Binop.op, &t1, &t2, &t3, &t4, &t5);
		switch (sizeofIRType(t1)) {
		case 1:
			res.hi = 0;
			res.lo &= 0xff;
			break;
		case 2:
			res.hi = 0;
			res.lo &= 0xffff;
			break;
		case 4:
			res.hi = 0;
			res.lo &= 0xffffffff;
			break;
		case 8:
			res.hi = 0;
			break;
		}
		return res;
	}
	case Iex_Unop: {
		struct expression_result arg;
		arg = eval_expression(thr, urs, e->Iex.Unop.arg, tmp);
		switch (e->Iex.Unop.op) {
		case Iop_8Uto16: case Iop_8Uto32: case Iop_8Uto64:
		case Iop_16Uto32:
		case Iop_32Uto64:
			return arg;
		default:
			abort();
		}
	}
	case Iex_Load: {
		struct expression_result addr;
		addr = eval_expression(thr, urs, e->Iex.Load.addr, tmp);
		_fetch_bytes(thr, addr.lo, &res,
			     sizeofIRType(e->Iex.Load.ty));
		return res;
	}
	case Iex_Const:
		switch (e->Iex.Const.con->tag) {
		case Ico_U1:
			abort();
		case Ico_U8:
			memcpy(&res, &e->Iex.Const.con->Ico, 1);
			break;
		case Ico_U16:
			memcpy(&res, &e->Iex.Const.con->Ico, 2);
			break;
		case Ico_U32:
			memcpy(&res, &e->Iex.Const.con->Ico, 4);
			break;
		case Ico_U64:
		case Ico_F64:
		case Ico_F64i:
			memcpy(&res, &e->Iex.Const.con->Ico, 8);
			break;
		case Ico_V128:
			res.lo = e->Iex.Const.con->Ico.V128;
			res.lo |= res.lo << 16;
			res.lo |= res.lo << 32;
			res.hi = res.lo;
			break;
		default:
			abort();
		}
		return res;
	default:
		abort();
	}
}

static void
handle_store(struct thread *thr,
	     const struct expression_result &addr,
	     const struct expression_result &data,
	     int size)
{
	store_bytes(thr, addr.lo, &data, size);
}

static int
sizeofIRExpr(IRTypeEnv *tyenv, IRExpr *e)
{
	return sizeofIRType(typeOfIRExpr(tyenv, e));
}

static const UChar parity_table[256] = {
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
};

static void
recalculate_eflags(struct augmented_regs *urs)
{
	int pf, cf, sf, zf, of;
	unsigned long dep1 = urs->cc_dep1;
	unsigned long dep2 = urs->cc_dep2;
	unsigned long ndep = urs->cc_ndep;

	pf = cf = sf = zf = of = 0;
	switch (urs->cc_op) {
	case AMD64G_CC_OP_COPY:
		urs->urs.eflags = urs->cc_dep1;
		return;

#define DO_ACT(name, type_tag, bits)					\
		case AMD64G_CC_OP_ ## name ## type_tag:			\
			ACTIONS_ ## name ((bits));			\
		        break
#define ACTION(name)							\
		DO_ACT(name, B, 7);					\
		DO_ACT(name, W, 15);					\
		DO_ACT(name, L, 31);					\
		DO_ACT(name, Q, 63)
/* A shift of 64 bits in a 64 bit type is undefined, so we can't just
   go (1ul << 64).  However, (1ul << 63) * 2 does the right thing. */
#define MASK(bits) ((1ul << bits) * 2ul - 1ul)
#define ACTIONS_ADD(bits)						\
		do {							\
			unsigned long res;				\
			res = (dep1 + dep2) & MASK(bits);		\
			cf = res < (dep1 & MASK(bits));			\
			zf = (res == 0ul);				\
			sf = (res >> bits);				\
			of = (~(dep1 ^ dep2) &				\
			      (dep1 ^ res)) >> bits;			\
			pf = (parity_table[res & 0xff]);		\
		} while (0)
#define ACTIONS_ADC(bits)	 		                        \
		do {							\
			unsigned long oldC = ndep & (AMD64G_CC_MASK_C); \
			unsigned long argR = dep2 ^ oldC;		\
			unsigned long res = ((dep1 + argR) + oldC) & MASK(bits); \
			if (oldC)					\
				cf = res <= (dep1 & MASK(bits));	\
			else						\
				cf = res < (dep1 & MASK(bits));		\
			zf = res == 0ul;				\
			sf = res >> bits;				\
			of = (~(dep1 ^ argR) & (dep1 ^ res)) >> bits;	\
			pf = (parity_table[res & 0xff]);		\
		} while (0)
#define ACTIONS_SUB(bits)						\
		do {							\
			unsigned long res;				\
			res = (dep1 - dep2) & MASK(bits);		\
			cf = (dep1 & MASK(bits)) < (dep2 & MASK(bits));	\
			zf = (res == 0ul);				\
			sf = res >> bits;				\
			of = ( (dep1 ^ dep2) &				\
			       (dep1 ^ res) ) >> bits;			\
			pf = (parity_table[res & 0xff]);		\
		} while (0)
#define ACTIONS_LOGIC(bits)						\
		do {							\
			cf = 0ul;					\
			zf = (dep1 & MASK(bits)) == 0ul;		\
			sf = (dep1 & MASK(bits)) >> bits;		\
			of = 0ul;					\
			pf = (parity_table[dep1 & 0xff]);		\
		} while (0)
#define ACTIONS_INC(bits)			                        \
		do {				                        \
			unsigned long res = dep1 & MASK(bits);		\
			cf = ndep & 1ul;				\
			zf = (res == 0ul);				\
			sf = res >> bits;				\
			of = res == (1ul << bits);			\
			pf = (parity_table[res & 0xff]);		\
		} while (0)
#define ACTIONS_DEC(bits)			                        \
		do {				                        \
			unsigned long res = dep1 & MASK(bits);		\
			cf = ndep & 1ul;				\
			zf = (res == 0ul);				\
			sf = res >> bits;				\
			of = ((res + 1ul) & MASK(bits)) == (1ul << bits); \
			pf = (parity_table[res & 0xff]);		\
		} while (0)
#define ACTIONS_SHR(bits)			                        \
		do {				                        \
			cf = dep2 & 1ul;				\
			zf = (dep1 == 0ul);				\
			sf = dep1 >> bits;				\
			of = (dep1 ^ dep2) >> bits;			\
			pf = (parity_table[dep1 & 0xff]);		\
		} while (0)
		ACTION(ADD);
		ACTION(SUB);
		ACTION(LOGIC);
		ACTION(INC);
		ACTION(DEC);
		ACTION(SHR);
		ACTION(ADC);
#undef DO_ACT
#undef ACTION
#undef ACTIONS_ADD
#undef ACTIONS_SUB
#undef ACTIONS_LOGIC
#undef ACTIONS_INC
#undef ACTIONS_DEC
#undef ACTIONS_SHR
#undef ACTIONS_ADC
	default:
		abort();
	}

	of &= 1;
	sf &= 1;
	zf &= 1;
	cf &= 1;
	pf &= 1;
	urs->urs.eflags &= ~(AMD64G_CC_MASK_O |
			     AMD64G_CC_MASK_S |
			     AMD64G_CC_MASK_Z |
			     AMD64G_CC_MASK_C |
			     AMD64G_CC_MASK_P);
	urs->urs.eflags |=
		(of << AMD64G_CC_SHIFT_O) |
		(sf << AMD64G_CC_SHIFT_S) |
		(zf << AMD64G_CC_SHIFT_Z) |
		(cf << AMD64G_CC_SHIFT_C) |
		(pf << AMD64G_CC_SHIFT_P);
}

extern "C" void
emulate_instruction(struct thread *thr)
{
	IRSB *irsb;
	unsigned char buf[16];
	TrivMemoryFetcher tmf(buf, 16);
	VexArchInfo vai;
	VexAbiInfo vabi;
	int x;
	struct expression_result *tmps;
	DisResult dr;
	struct augmented_regs urs;

	get_regs(thr, &urs.urs);
	urs.cc_op = AMD64G_CC_OP_COPY;
	urs.cc_dep1 = urs.urs.eflags;
	urs.cc_dep2 = 0;
	urs.cc_ndep = 0;

	_fetch_bytes(thr, urs.urs.rip, buf, 16);
	LibVEX_default_VexArchInfo(&vai);
	LibVEX_default_VexAbiInfo(&vabi);
	vabi.guest_stack_redzone_size = 128;
	irsb = emptyIRSB();
	dr = disInstr_AMD64(irsb, False, resteerOkFn,
			    NULL, tmf, 0,
			    urs.urs.rip, VexArchAMD64,
			    &vai, &vabi,
			    False);

	tmps = (struct expression_result *)alloca(sizeof(tmps[0]) * irsb->tyenv->types_used);
	memset(tmps, 0xab, sizeof(tmps[0]) * irsb->tyenv->types_used);
	for (x = 0; x < irsb->stmts_used; x++) {
		switch (irsb->stmts[x]->tag) {
		case Ist_Put:
			handle_put(&urs,
				   irsb->stmts[x]->Ist.Put.offset,
				   eval_expression(thr,
						   &urs,
						   irsb->stmts[x]->Ist.Put.data,
						   tmps),
				   sizeofIRExpr(irsb->tyenv,
						irsb->stmts[x]->Ist.Put.data));
			break;
		case Ist_WrTmp:
			tmps[irsb->stmts[x]->Ist.WrTmp.tmp] =
				eval_expression(thr, &urs,
						irsb->stmts[x]->Ist.WrTmp.data,
						tmps);
			break;
		case Ist_Store:
			handle_store(thr,
				     eval_expression(thr, &urs,
						     irsb->stmts[x]->Ist.Store.addr,
						     tmps),
				     eval_expression(thr, &urs,
						     irsb->stmts[x]->Ist.Store.data,
						     tmps),
				     sizeofIRExpr(irsb->tyenv,
						  irsb->stmts[x]->Ist.Store.data));
			break;
		case Ist_Exit:
			assert(irsb->stmts[x]->Ist.Exit.jk == Ijk_Boring);
			if (eval_expression(thr, &urs,
					    irsb->stmts[x]->Ist.Exit.guard,
					    tmps).lo) {
				urs.urs.rip = irsb->stmts[x]->Ist.Exit.dst->Ico.U64;
				goto done;
			}
			break;

		default:
			ppIRStmt(irsb->stmts[x]);
			printf("\n");
			abort();
		}
	}

	switch (dr.whatNext) {
	case DisResult::Dis_StopHere:
		abort();
	case DisResult::Dis_Continue:
		urs.urs.rip += dr.len;
		break;
	case DisResult::Dis_Resteer:
		urs.urs.rip = dr.continueAt;
		break;
	default:
		abort();
	}

done:
	recalculate_eflags(&urs);

	set_regs(thr, &urs.urs);
}
