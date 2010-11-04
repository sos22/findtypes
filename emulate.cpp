/* Simple interface to VEX for doing isntruction emulation */
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

static int
libvex_offset_to_linux_offset(int offset)
{
	switch (offset) {
#define reg(vex_name, linux_name)					\
		case OFFSET_amd64_ ## vex_name:				\
			return offsetof(struct user_regs_struct,	\
					linux_name)
		reg(RAX, rax);
		reg(RBX, rbx);
		reg(RCX, rcx);
		reg(RDX, rdx);
		reg(RSP, rsp);
		reg(RBP, rbp);
		reg(RSI, rsi);
		reg(RDI, rdi);
#undef reg
	default:
		abort();
	}
}

static void
handle_put(struct user_regs_struct *urs,
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
		const struct user_regs_struct *urs,
		IRExpr *e,
		const struct expression_result *tmp)
{
	struct expression_result res;
	memset(&res, 0, sizeof(res));
	switch (e->tag) {
	case Iex_Get: {
		unsigned o = libvex_offset_to_linux_offset(e->Iex.Get.offset);
		memcpy(&res, (void *)((unsigned long)urs + o), sizeofIRType(e->Iex.Get.ty));
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
		case Iop_Add64:
			res.lo = arg1.lo + arg2.lo;
			break;
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

extern "C" void
emulate_instruction(struct thread *thr)
{
	IRSB *irsb;
	unsigned char buf[16];
	struct user_regs_struct urs;
	TrivMemoryFetcher tmf(buf, 16);
	VexArchInfo vai;
	VexAbiInfo vabi;
	int x;
	struct expression_result *tmps;
	DisResult dr;

	get_regs(thr, &urs);
	_fetch_bytes(thr, urs.rip, buf, 16);
	LibVEX_default_VexArchInfo(&vai);
	LibVEX_default_VexAbiInfo(&vabi);
	vabi.guest_stack_redzone_size = 128;
	irsb = emptyIRSB();
	dr = disInstr_AMD64(irsb, False, resteerOkFn,
			    NULL, tmf, 0,
			    urs.rip, VexArchAMD64,
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
		urs.rip += dr.len;
		break;
	case DisResult::Dis_Resteer:
		urs.rip = dr.continueAt;
		break;
	default:
		abort();
	}

	set_regs(thr, &urs);
}
