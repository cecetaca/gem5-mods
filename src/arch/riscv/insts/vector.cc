/*
 * Copyright (c) 2022 PLCT Lab
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "arch/riscv/insts/vector.hh"

#include <sstream>
#include <string>

#include "arch/riscv/insts/static_inst.hh"
#include "arch/riscv/isa.hh"
#include "arch/riscv/regs/misc.hh"
#include "arch/riscv/regs/vector.hh"
#include "arch/riscv/utility.hh"
#include "cpu/static_inst.hh"
#include "cpu/thread_context.hh"
#include "mem/packet_access.hh"

namespace gem5
{

namespace RiscvISA
{

/**
 * This function translates the 3-bit value of vlmul bits to the corresponding
 * lmul value as specified in RVV 1.0 spec p11-12 chapter 3.4.2.
 *
 * I.e.,
 * vlmul = -3 -> LMUL = 1/8
 * vlmul = -2 -> LMUL = 1/4
 * vlmul = -1 -> LMUL = 1/2
 * vlmul = 0 -> LMUL = 1
 * vlmul = 1 -> LMUL = 2
 * vlmul = 2 -> LMUL = 4
 * vlmul = 3 -> LMUL = 8
 *
**/
float
getVflmul(uint32_t vlmul_encoding)
{
    int vlmul = sext<3>(vlmul_encoding & 7);
    float vflmul = vlmul >= 0 ? 1 << vlmul : 1.0 / (1 << -vlmul);
    return vflmul;
}

uint32_t
getVlmax(VTYPE vtype, uint32_t vlen)
{
    uint32_t sew = getSew(vtype.vsew);
    // vlmax is defined in RVV 1.0 spec p12 chapter 3.4.2.
    uint32_t vlmax = (vlen/sew) * getVflmul(vtype.vlmul);
    return vlmax;
}

std::string
VConfOp::generateDisassembly(Addr pc, const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", ";
    if (bit31 && bit30 == 0) {
        ss << registerName(srcRegIdx(0)) << ", " << registerName(srcRegIdx(1));
    } else if (bit31 && bit30) {
        ss << uimm << ", " << generateZimmDisassembly();
    } else {
        ss << registerName(srcRegIdx(0)) << ", " << generateZimmDisassembly();
    }
    return ss.str();
}

std::string
VConfOp::generateZimmDisassembly() const
{
    std::stringstream s;

    // VSETIVLI uses ZIMM10 and VSETVLI uses ZIMM11
    uint64_t zimm = (bit31 && bit30) ? zimm10 : zimm11;

    bool frac_lmul = bits(zimm, 2);
    int sew = 1 << (bits(zimm, 5, 3) + 3);
    int lmul = bits(zimm, 1, 0);
    auto vta = bits(zimm, 6) == 1 ? "ta" : "tu";
    auto vma = bits(zimm, 7) == 1 ? "ma" : "mu";
    s << "e" << sew;
    if (frac_lmul) {
        std::string lmul_str = "";
        switch(lmul){
        case 3:
            lmul_str = "f2";
            break;
        case 2:
            lmul_str = "f4";
            break;
        case 1:
            lmul_str = "f8";
            break;
        default:
            panic("Unsupport fractional LMUL");
        }
        s << ", m" << lmul_str;
    } else {
        s << ", m" << (1 << lmul);
    }
    s << ", " << vta << ", " << vma;
    return s.str();
}

std::string
VectorNonSplitInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", "
        << registerName(srcRegIdx(0));
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorArithMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", ";
    if (machInst.funct3 == 0x3) {
        // OPIVI
      ss  << registerName(srcRegIdx(0)) << ", " << machInst.vecimm;
    } else {
      ss  << registerName(srcRegIdx(1)) << ", " << registerName(srcRegIdx(0));
    }
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorArithMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", ";
    if (machInst.funct3 == 0x3) {
        // OPIVI
      ss  << registerName(srcRegIdx(0)) << ", " << machInst.vecimm;
    } else {
      ss  << registerName(srcRegIdx(1)) << ", " << registerName(srcRegIdx(0));
    }
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorVMUNARY0MicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0));
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorVMUNARY0MacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0));
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorSlideMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) <<  ", ";
    if (machInst.funct3 == 0x3) {
      ss  << registerName(srcRegIdx(0)) << ", "
        << registerName(srcRegIdx(1)) << ", " << machInst.vecimm;
    } else {
      ss  << registerName(srcRegIdx(1)) << ", "
        << registerName(srcRegIdx(2)) << ", " << registerName(srcRegIdx(0));
    }
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VectorSlideMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", ";
    if (machInst.funct3 == 0x3) {
      ss  << registerName(srcRegIdx(0)) << ", " << machInst.vecimm;
    } else {
      ss  << registerName(srcRegIdx(1)) << ", " << registerName(srcRegIdx(0));
    }
    if (machInst.vm == 0) ss << ", v0.t";
    return ss.str();
}

std::string VleMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    unsigned vlenb = vlen >> 3;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", "
       << vlenb * microIdx << '(' << registerName(srcRegIdx(0)) << ')' << ", "
       << registerName(srcRegIdx(1));
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VlWholeMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    unsigned vlenb = vlen >> 3;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", "
       << vlenb * microIdx << '(' << registerName(srcRegIdx(0)) << ')';
    return ss.str();
}

std::string VseMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    unsigned vlenb = vlen >> 3;
    ss << mnemonic << ' ' << registerName(srcRegIdx(1)) << ", "
       << vlenb * microIdx  << '(' << registerName(srcRegIdx(0)) << ')';
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VsWholeMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    unsigned vlenb = vlen >> 3;
    ss << mnemonic << ' ' << registerName(srcRegIdx(1)) << ", "
       << vlenb * microIdx << '(' << registerName(srcRegIdx(0)) << ')';
    return ss.str();
}

std::string VleMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VlWholeMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    return ss.str();
}

std::string VseMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(1)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VsWholeMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(1)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    return ss.str();
}

std::string VlElementMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    if (has_rs2) {
        ss << ", " << registerName(srcRegIdx(1));
    }
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

std::string VlElementMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    if (has_rs2) {
        ss << ", " << registerName(srcRegIdx(1));
    }
    if (microIdx != 0 || machInst.vtype8.vma == 0 || machInst.vtype8.vta == 0)
        ss << ", " << registerName(srcRegIdx(has_rs2 ? 2 : 1));
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

std::string VsElementMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(has_rs2 ? 2 : 1))
        << ", " << '(' << registerName(srcRegIdx(0)) << ')';
    if (has_rs2) {
        ss << ", " << registerName(srcRegIdx(1));
    }
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VsElementMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(2)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')';
    if (has_rs2) {
        ss << ", " << registerName(srcRegIdx(1));
    }
    if (microIdx != 0 || machInst.vtype8.vma == 0 || machInst.vtype8.vta == 0)
        ss << ", " << registerName(srcRegIdx(has_rs2 ? 2 : 1));
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VlIndexMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", "
        << '(' << registerName(srcRegIdx(0)) << "),"
        << registerName(srcRegIdx(1));
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VlIndexMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' '
        << registerName(destRegIdx(0)) << "[" << uint16_t(vdElemIdx) << "], "
        << '(' << registerName(srcRegIdx(0)) << "), "
        << registerName(srcRegIdx(1)) << "[" << uint16_t(vs2ElemIdx) << "]";
    if (microIdx != 0 || machInst.vtype8.vma == 0 || machInst.vtype8.vta == 0)
        ss << ", " << registerName(srcRegIdx(2));
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VsIndexMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(2)) << ", "
        << '(' << registerName(srcRegIdx(0)) << "),"
        << registerName(srcRegIdx(1));
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string VsIndexMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' '
        << registerName(srcRegIdx(2)) << "[" << uint16_t(vs3ElemIdx) << "], "
        << '(' << registerName(srcRegIdx(0)) << "), "
        << registerName(srcRegIdx(1)) << "[" << uint16_t(vs2ElemIdx) << "]";
    if (!machInst.vm) ss << ", v0.t";
    return ss.str();
}

std::string
VMvWholeMacroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        registerName(srcRegIdx(1));
    return ss.str();
}

std::string
VMvWholeMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        registerName(srcRegIdx(1));
    return ss.str();
}

VMaskMergeMicroInst::VMaskMergeMicroInst(ExtMachInst extMachInst,
    uint8_t _dstReg, uint8_t _numSrcs, uint32_t _elen, uint32_t _vlen,
    size_t _elemSize)
    : VectorArithMicroInst("vmask_mv_micro", extMachInst,
                            SimdAddOp, 0, 0, _elen, _vlen),
      elemSize(_elemSize)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;

    setDestRegIdx(_numDestRegs++, vecRegClass[_dstReg]);
    _numTypedDestRegs[VecRegClass]++;
    for (uint8_t i=0; i<_numSrcs; i++) {
        setSrcRegIdx(_numSrcRegs++, vecRegClass[VecMemInternalReg0 + i]);
    }
}

Fault
VMaskMergeMicroInst::execute(ExecContext* xc,
    trace::InstRecord* traceData) const
{
    vreg_t& tmp_d0 = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    auto Vd = tmp_d0.as<uint8_t>();
    uint32_t vlenb = vlen >> 3;
    const uint32_t elems_per_vreg = vlenb / elemSize;
    size_t bit_cnt = 0;

    // mask tails are always treated as agnostic: writting 1s
    tmp_d0.set(0xff);

    vreg_t tmp_s;
    for (uint8_t i = 0; i < this->_numSrcRegs; i++) {
        xc->getRegOperand(this, i, &tmp_s);
        auto s = tmp_s.as<uint8_t>();
        if (elems_per_vreg < 8) {
            const uint32_t m = (1 << elems_per_vreg) - 1;
            const uint32_t mask = m << (i * elems_per_vreg % 8);
            // clr & ext bits
            Vd[bit_cnt/8] ^= Vd[bit_cnt/8] & mask;
            Vd[bit_cnt/8] |= s[bit_cnt/8] & mask;
            bit_cnt += elems_per_vreg;
        } else {
            const uint32_t byte_offset = elems_per_vreg / 8;
            memcpy(Vd + i * byte_offset, s + i * byte_offset, byte_offset);
        }
    }
    if (traceData) {
        traceData->setData(vecRegClass, &tmp_d0);
    }
    return NoFault;
}

std::string
VMaskMergeMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0));
    for (uint8_t i = 0; i < this->_numSrcRegs; i++) {
        ss << ", " << registerName(srcRegIdx(i));
    }
    unsigned vlenb = vlen >> 3;
    ss << ", offset:" << vlenb / elemSize;
    return ss.str();
}

Fault
VxsatMicroInst::execute(ExecContext* xc, trace::InstRecord* traceData) const
{
    xc->setMiscReg(MISCREG_VXSAT, *vxsat);
    auto vcsr = xc->readMiscReg(MISCREG_VCSR);
    xc->setMiscReg(MISCREG_VCSR, ((vcsr&~1)|*vxsat));
    return NoFault;
}

std::string
VxsatMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << "VXSAT" << ", " << (*vxsat ? "0x1" : "0x0");
    return ss.str();
}

VlFFTrimVlMicroOp::VlFFTrimVlMicroOp(ExtMachInst _machInst, uint32_t _microVl,
    uint32_t _microIdx, uint32_t _elen, uint32_t _vlen,
    std::vector<StaticInstPtr>& _microops)
    : VectorMicroInst("vlff_trimvl_v_micro", _machInst, SimdConfigOp,
                      _microVl, _microIdx, _elen, _vlen),
      microops(_microops)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        nullptr
    );

    // Create data dependency with load micros
    for (uint8_t i=0; i<microIdx; i++) {
        setSrcRegIdx(_numSrcRegs++, vecRegClass[_machInst.vd + i]);
    }

    this->flags[IsControl] = true;
    this->flags[IsIndirectControl] = true;
    this->flags[IsInteger] = true;
    this->flags[IsUncondControl] = true;
}

uint32_t
VlFFTrimVlMicroOp::calcVl() const
{
    uint32_t vl = 0;
    for (uint8_t i=0; i<microIdx; i++) {
        VleMicroInst& micro = static_cast<VleMicroInst&>(*microops[i]);
        vl += micro.faultIdx;

        if (micro.trimVl)
            break;
    }
    return vl;
}

Fault
VlFFTrimVlMicroOp::execute(ExecContext *xc, trace::InstRecord *traceData) const
{
    auto tc = xc->tcBase();
    bool set_dirty = false;
    bool check_vill = false;
    Fault update_fault = updateVPUStatus(xc, machInst, set_dirty, check_vill);
    if (update_fault != NoFault) { return update_fault; }

    PCState pc;
    set(pc, xc->pcState());

    uint32_t new_vl = calcVl();

    tc->setMiscReg(MISCREG_VSTART, 0);

    RegVal final_val = new_vl;
    if (traceData) {
        traceData->setData(miscRegClass, final_val);
    }

    pc.vl(new_vl);
    pc.new_vconf(true);
    xc->pcState(pc);

    return NoFault;
}

std::unique_ptr<PCStateBase>
VlFFTrimVlMicroOp::branchTarget(ThreadContext *tc) const
{
    PCStateBase *pc_ptr = tc->pcState().clone();

    uint32_t new_vl = calcVl();

    pc_ptr->as<PCState>().vl(new_vl);
    return std::unique_ptr<PCStateBase>{pc_ptr};
}

std::string
VlFFTrimVlMicroOp::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << " vl";
    return ss.str();
}

std::string VlSegMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')' <<
        ", " << registerName(srcRegIdx(1));
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

std::string VlSegMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')' <<
        ", "<< registerName(srcRegIdx(1));
    if (microIdx != 0 || machInst.vtype8.vma == 0 || machInst.vtype8.vta == 0)
        ss << ", " << registerName(srcRegIdx(2));
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

VlSegDeIntrlvMicroInst::VlSegDeIntrlvMicroInst(ExtMachInst extMachInst,
                        uint32_t _micro_vl, uint32_t _dstReg,
                        uint32_t _numSrcs, uint32_t _microIdx,
                        uint32_t _numMicroops, uint32_t _field, uint32_t _elen,
                        uint32_t _vlen, uint32_t _sizeOfElement)
    : VectorArithMicroInst("vlseg_deintrlv_micro", extMachInst,
                            SimdAddOp, 0, 0, _elen, _vlen)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;
    numSrcs = _numSrcs;
    numMicroops = _numMicroops;
    field =_field;
    sizeOfElement = _sizeOfElement;
    microIdx = _microIdx;
    micro_vl = _micro_vl;

    setDestRegIdx(_numDestRegs++, vecRegClass[_dstReg]);
    _numTypedDestRegs[VecRegClass]++;
    for (uint32_t i=0; i < _numSrcs; i++) {
        uint32_t index = VecMemInternalReg0 + i + (microIdx * _numSrcs);
        setSrcRegIdx(_numSrcRegs++, vecRegClass[index]);
    }

    if (!extMachInst.vtype8.vta
        || (!extMachInst.vm && !extMachInst.vtype8.vma)) {
        oldDstIdx = _numSrcRegs;
        setSrcRegIdx(_numSrcRegs++, destRegIdxArr[0]);
    }
    if (!extMachInst.vm) {
        vmsrcIdx = _numSrcRegs;
        setSrcRegIdx(_numSrcRegs++, vecRegClass[0]);
    }
}

Fault
VlSegDeIntrlvMicroInst::execute(ExecContext* xc, trace::InstRecord* traceData) const
{
    vreg_t& tmp_d0 = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    auto Vd = tmp_d0.as<uint8_t>();
    const uint32_t elems_per_vreg = micro_vl;
    vreg_t tmp_s;
    auto s = tmp_s.as<uint8_t>();
    uint32_t elem = 0;
    uint32_t index = field;

    vreg_t tmp_v0;
    uint8_t *v0;
    if (!machInst.vm) {
        xc->getRegOperand(this, vmsrcIdx, &tmp_v0);
        v0 = tmp_v0.as<uint8_t>();
    }

    const size_t micro_vlmax = vlen / width_EEW(machInst.width);

    if (!machInst.vtype8.vta || (!machInst.vm && !machInst.vtype8.vma)) {
        RiscvISA::vreg_t old_vd;
        xc->getRegOperand(this, oldDstIdx, &old_vd);
        tmp_d0 = old_vd;
    } else {
        tmp_d0.set(0xff);
    }

    for (uint32_t i = 0; i < numSrcs; i++) {
        xc->getRegOperand(this, i, &tmp_s);
        s = tmp_s.as<uint8_t>();

        while (index < (i + 1) * elems_per_vreg)
        {
            size_t ei = elem + micro_vlmax * microIdx;
            if (machInst.vm || elem_mask(v0, ei)) {
                memcpy(Vd + (elem * sizeOfElement),
                       s + ((index % elems_per_vreg) * sizeOfElement),
                       sizeOfElement);
            }
            index += numSrcs;
            elem++;
        }
    }

    if (traceData) {
        traceData->setData(vecRegClass, &tmp_d0);
    }
    return NoFault;
}

std::string
VlSegDeIntrlvMicroInst::generateDisassembly(Addr pc, const loader::SymbolTable *symtab)
    const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0));
    for (uint8_t i = 0; i < this->_numSrcRegs; i++) {
        ss << ", " << registerName(srcRegIdx(i));
    }
    ss << ", field: " << field;
    return ss.str();
}

std::string VsSegMacroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(srcRegIdx(1)) << ", " << '('
       << registerName(srcRegIdx(0)) << ')';
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

std::string VsSegMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", " <<
        '(' << registerName(srcRegIdx(0)) << ')' <<
        ", "<< registerName(srcRegIdx(1));
    if (!machInst.vm)
        ss << ", v0.t";
    return ss.str();
}

VsSegIntrlvMicroInst::VsSegIntrlvMicroInst(ExtMachInst extMachInst,
                        uint32_t _micro_vl, uint32_t _dstReg,
                        uint32_t _numSrcs, uint32_t _microIdx,
                        uint32_t _numMicroops, uint32_t _field, uint32_t _elen,
                        uint32_t _vlen, uint32_t _sizeOfElement)
    : VectorArithMicroInst("vsseg_reintrlv_micro", extMachInst,
                            SimdAddOp, 0, 0, _elen, _vlen)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;
    numSrcs = _numSrcs;
    numMicroops = _numMicroops;
    field =_field;
    sizeOfElement = _sizeOfElement;
    microIdx = _microIdx;
    micro_vl = _micro_vl;

    setDestRegIdx(_numDestRegs++, vecRegClass[VecMemInternalReg0 + field +
        (_microIdx * numSrcs)]);

    _numTypedDestRegs[VecRegClass]++;
    for (uint8_t i=0; i<_numSrcs; i++) {
        setSrcRegIdx(_numSrcRegs++, vecRegClass[_dstReg + (i * numMicroops) +
            (microIdx)]);
    }
}

Fault
VsSegIntrlvMicroInst::execute(ExecContext* xc,
    trace::InstRecord* traceData) const
{
    const uint32_t elems_per_vreg = micro_vl;
    vreg_t& tmp_d0 = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    auto Vd = tmp_d0.as<uint8_t>();

    vreg_t tmp_s;
    auto s = tmp_s.as<uint8_t>();
    xc->getRegOperand(this, 0, &tmp_s);
    s = tmp_s.as<uint8_t>();

    uint32_t indexVd = 0;
    uint32_t srcReg = (field * elems_per_vreg) % numSrcs;
    uint32_t indexs = (field * elems_per_vreg) / numSrcs;

    while (indexVd < elems_per_vreg) {
        xc->getRegOperand(this, srcReg, &tmp_s);
        s = tmp_s.as<uint8_t>();

        memcpy(Vd + (indexVd * sizeOfElement),
                    s + (indexs * sizeOfElement),
                    sizeOfElement);

        indexVd++;
        srcReg++;
        if (srcReg >= numSrcs) {
            srcReg = 0;
            indexs++;
        }
    }

    if (traceData) {
        traceData->setData(vecRegClass, &tmp_d0);
    }
    return NoFault;
}

std::string
VsSegIntrlvMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0));
    for (uint8_t i = 0; i < this->_numSrcRegs; i++) {
        ss << ", " << registerName(srcRegIdx(i));
    }
    ss << ", field: " << field;
    return ss.str();
}

VCpyVsMicroInst::VCpyVsMicroInst(ExtMachInst _machInst, uint32_t _microIdx,
                                 uint8_t _vsRegIdx, uint32_t _elen,
                                 uint32_t _vlen)
    : VectorArithMicroInst("vcpyvs_v_micro", _machInst, SimdMiscOp, 0,
                           _microIdx, _elen, _vlen)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;
    setDestRegIdx(_numDestRegs++, vecRegClass[VecMemInternalReg0 + _microIdx]);
    _numTypedDestRegs[VecRegClass]++;
    setSrcRegIdx(_numSrcRegs++, vecRegClass[_vsRegIdx + _microIdx]);
}

Fault
VCpyVsMicroInst::execute(ExecContext* xc, trace::InstRecord* traceData) const
{
    bool set_dirty = true;
    bool check_vill = false;
    Fault update_fault = updateVPUStatus(xc, machInst, set_dirty, check_vill);
    if (update_fault != NoFault) { return update_fault; }

    // copy vector source reg to vtmp
    vreg_t& vtmp = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    vreg_t vs;
    xc->getRegOperand(this, 0, &vs);
    vtmp = vs;

    if (traceData) {
        traceData->setData(vecRegClass, &vtmp);
    }

    return NoFault;
}

std::string
VCpyVsMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", "
       << registerName(srcRegIdx(0));
    return ss.str();
}

VPinVdMicroInst::VPinVdMicroInst(ExtMachInst _machInst, uint32_t _microIdx,
                                 uint32_t _numVdPins, uint32_t _elen,
                                 uint32_t _vlen, bool _hasVdOffset)
    : VectorArithMicroInst("vpinvd_v_micro", _machInst, SimdMiscOp, 0,
                           _microIdx, _elen, _vlen),
      hasVdOffset(_hasVdOffset)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;
    setDestRegIdx(_numDestRegs++, vecRegClass[_machInst.vd + _microIdx]);
    _numTypedDestRegs[VecRegClass]++;
    if (!_machInst.vtype8.vta || (!_machInst.vm && !_machInst.vtype8.vma)
                              || hasVdOffset) {
        setSrcRegIdx(_numSrcRegs++, vecRegClass[_machInst.vd + _microIdx]);
    }
    RegId Vd = destRegIdx(0);
    Vd.setNumPinnedWrites(_numVdPins);
    setDestRegIdx(0, Vd);
}

Fault
VPinVdMicroInst::execute(ExecContext* xc, trace::InstRecord* traceData) const
{
    bool set_dirty = true;
    bool check_vill = false;
    Fault update_fault = updateVPUStatus(xc, machInst, set_dirty, check_vill);
    if (update_fault != NoFault) { return update_fault; }

    // tail/mask policy: both undisturbed if one is, 1s if none
    vreg_t& vd = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    if (!machInst.vtype8.vta || (!machInst.vm && !machInst.vtype8.vma)
                            || hasVdOffset) {
        vreg_t old_vd;
        xc->getRegOperand(this, 0, &old_vd);
        vd = old_vd;
    } else {
        vd.set(0xff);
    }

    if (traceData) {
        traceData->setData(vecRegClass, &vd);
    }

    return NoFault;
}

std::string
VPinVdMicroInst::generateDisassembly(Addr pc,
        const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << ' ' << registerName(destRegIdx(0)) << ", ";

    if (!machInst.vtype8.vta || (!machInst.vm && !machInst.vtype8.vma)
                             || hasVdOffset) {
        ss << registerName(srcRegIdx(0));
    } else {
        ss << "~0";
    }

    return ss.str();
}


/* --- vector offload (see vec_offload.hh) --- */

bool VecOffload::enabled = false;
bool VecOffload::decoupledMem = true;
bool VecOffload::vconfFromStorage = false;
VecOffloadBackend *VecOffload::backend = nullptr;

VecOffloadMicroInst::VecOffloadMicroInst(ExtMachInst _machInst,
    const char *mnem, uint32_t _elen, uint32_t _vlen)
    : VectorMicroInst(mnem, _machInst, SimdMiscOp,
                      _machInst.vl, 0, _elen, _vlen)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));

    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec.rawInst = _machInst.all;
    rec.vfunct6 = _machInst.vfunct6;
    rec.funct3 = _machInst.funct3;
    rec.opClass = VecOffloadArith;
    rec.vd = _machInst.rd;
    rec.vs1 = _machInst.rs1;
    rec.vs2 = _machInst.rs2;
    rec.vm = _machInst.vm;
    rec.vsew = _machInst.vtype8.vsew;
    rec.vlmul = _machInst.vtype8.vlmul;
    rec.vta = _machInst.vtype8.vta;
    rec.vma = _machInst.vtype8.vma;
    rec.vl = _machInst.vl;
    rec.vstart = 0;  // enforced at execute

    // funct3: 0=OPIVV 1=OPFVV 2=OPMVV 3=OPIVI 4=OPIVX 5=OPFVF 6=OPMVX
    switch (rec.funct3) {
      case 0x4:
      case 0x6:
        scalarSrc = 1;
        setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs1]);
        break;
      case 0x5:
        scalarSrc = 2;
        setSrcRegIdx(_numSrcRegs++, floatRegClass[_machInst.rs1]);
        break;
      default:
        scalarSrc = 0;
        break;
    }

    // funct6 0x17 is vmerge/vmv.v.*: one opcode whose source is a
    // vector register when the form is OPIVV, or whenever it is masked
    // (the mask selects between two vector operands). Those are moves
    // of register contents, not arithmetic; the unmasked scalar and
    // immediate forms are plain broadcasts and stay arithmetic.
    if ((rec.vfunct6 == 0x17 && (rec.funct3 == 0x0 || rec.vm == 0)) ||
        (rec.vfunct6 == 0x27 && rec.funct3 == 0x3)) {
        // ...and funct6 0x27 in the OPIVI slot is vmvNr.v, the
        // whole-register move: also a register-to-register copy, just
        // one that ignores vl and vtype entirely.
        rec.opClass = VecOffloadCopy;
    }

    // Deliberately NOT IsNonSpeculative: the record is emitted from
    // the commit stage (commitOffload below), which provides the same
    // three guarantees head-execution used to buy -- wrong-path
    // exclusion (only committing instructions emit), program order
    // (commit order), and architectural register reads (every older
    // instruction has retired) -- without the ~6-cycle NonSpec
    // schedule/execute/writeback round trip per instruction. execute()
    // is a no-op apart from the fault check, so the micro-op is
    // already complete when it reaches the ROB head and retires at
    // full commit width.
}

Fault
VecOffloadMicroInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered (is the ActUnit configured?)");

    if (xc->readMiscReg(MISCREG_VSTART) != 0) {
        return std::make_shared<IllegalInstFault>(
            "vector_offload: vstart != 0 unsupported (phase 1)",
            machInst);
    }
    return NoFault;
}


namespace {

// vl and vtype are ARCHITECTURAL state, but the offload record captures
// them when the instruction is CONSTRUCTED, i.e. at decode. The
// decoder's own copy is refreshed only when it is handed a PCState
// carrying new_vconf, and on MinorCPU that does not reliably reach it
// for every instruction after a vsetvl -- a correctly-predicted branch
// does not redirect fetch, so the decoder keeps the vl it had.
//
// The failure is silent and specific: a strip-mined loop whose vl never
// changes is fine, and the short FINAL chunk is not. The unit then
// operates on VLMAX elements instead of the trimmed count, reading
// whatever the register still held past the end of the chunk. It took a
// per-chunk population count to see it -- the totals looked plausible
// because every element still landed in some bin.
//
// Reading the CSRs where the record is issued removes the dependence on
// decode-time capture entirely. These micro-ops are non-speculative and
// issue at the commit point, so the architectural values are exactly
// the ones the instruction must use.
// Where the authoritative vl/vtype live depends on the CPU model; see
// the note in refreshVConf for why the two models must read different
// storage.
uint32_t
readArchVl(ThreadContext *tc)
{
    return VecOffload::vconfFromStorage
        ? (uint32_t)tc->readMiscRegNoEffect(MISCREG_VL)
        : (uint32_t)tc->readMiscReg(MISCREG_VL);
}

RegVal
readArchVtype(ThreadContext *tc)
{
    return VecOffload::vconfFromStorage
        ? tc->readMiscRegNoEffect(MISCREG_VTYPE)
        : tc->readMiscReg(MISCREG_VTYPE);
}

void
refreshVConf(VecOffloadRecord &r, ThreadContext *tc)
{
    // Where the authoritative vl/vtype live depends on the CPU model.
    //
    // The plain read derives them from the PCState, which is correct on
    // O3 and stale on Minor after a trimming vsetvl (the decoder's copy
    // oscillates when a line fetched before the redirect is decoded
    // after it). vsetvl therefore also records the configuration in
    // MiscReg storage, which advances only when a vsetvl EXECUTES.
    //
    // That storage is right on Minor, where execute IS commit, and
    // WRONG on O3, where a younger vsetvl can execute speculatively and
    // overwrite it before an older offload micro-op commits -- which
    // showed up immediately as every record carrying the last vsetvl's
    // configuration instead of its own.
    r.vl = readArchVl(tc);
    VTYPE vt = readArchVtype(tc);
    r.vsew = vt.vsew;
    r.vlmul = vt.vlmul;
    r.vta = vt.vta;
    r.vma = vt.vma;
}

// A mask transfer (vlm.v/vsm.v) moves ceil(vl/8) BYTES, and that byte
// count is computed at decode -- so it goes stale on Minor for exactly
// the reason above, and skipping the refresh to protect the byte count
// preserves the staleness instead of fixing it.
//
// The symptom is a short store: a 4096-element mask writes the 49 bytes
// some earlier, shorter vsetvl called for and leaves the remaining 463
// untouched, so a scan of the stored mask silently misses every match
// past the first 392 elements. reverse_index's dedup walk is built on
// exactly that scan, and answered 9800 unique links against a true
// 8347 -- every miss appending a duplicate.
//
// Whole-register transfers need no equivalent: their byte count is
// nf*VLENB, which does not depend on vl at all.
void
refreshMaskVConf(VecOffloadRecord &r, ThreadContext *tc)
{
    r.vl = (readArchVl(tc) + 7) / 8;
}

} // anonymous namespace

bool
VecOffloadMicroInst::commitOffload(uint64_t seqNum, ThreadContext *tc) const
{
    if (tc->readMiscRegNoEffect(MISCREG_VSTART) != 0) {
        return true;  // execute()'s fault will handle it; no record
    }
    if (VecOffload::backend->arithQueueFull()) {
        return false;  // bounded queue: stall at the head and retry
    }
    VecOffloadRecord r = rec;
    refreshVConf(r, tc);
    r.vstart = 0;
    if (scalarSrc == 1) {
        r.scalar = tc->getReg(intRegClass[machInst.rs1]);
    } else if (scalarSrc == 2) {
        r.scalar = tc->getReg(floatRegClass[machInst.rs1]);
    }
    VecOffload::backend->issueArith(r);
    return true;
}

std::string
VecOffloadMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << "_voffload";
    return ss.str();
}

namespace
{

VecOffloadRecord
buildVecOffloadRecord(ExtMachInst emi)
{
    VecOffloadRecord r;
    r.rawInst = emi.all;
    r.vfunct6 = emi.vfunct6;
    r.funct3 = emi.funct3;
    r.opClass = VecOffloadArith;
    r.vd = emi.rd;
    r.vs1 = emi.rs1;
    r.vs2 = emi.rs2;
    r.vm = emi.vm;
    r.vsew = emi.vtype8.vsew;
    r.vlmul = emi.vtype8.vlmul;
    r.vta = emi.vtype8.vta;
    r.vma = emi.vtype8.vma;
    r.vl = emi.vl;
    r.vstart = 0;
    return r;
}

} // anonymous namespace

VecOffloadNonSplitInst::VecOffloadNonSplitInst(ExtMachInst _machInst,
    const char *mnem)
    : RiscvStaticInst(mnem, _machInst, SimdMiscOp)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));
    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec = buildVecOffloadRecord(_machInst);

    switch (rec.funct3) {
      case 0x6:  // OPMVX (vmv.s.x)
        scalarSrc = 1;
        setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs1]);
        break;
      case 0x5:  // OPFVF (vfmv.s.f)
        scalarSrc = 2;
        setSrcRegIdx(_numSrcRegs++, floatRegClass[_machInst.rs1]);
        break;
      default:
        scalarSrc = 0;
        break;
    }

    this->flags[IsVector] = true;
    // Speculative like VecOffloadMicroInst: the record leaves from
    // the commit stage, not from execution at the head.
}

Fault
VecOffloadNonSplitInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered");
    if (xc->readMiscReg(MISCREG_VSTART) != 0) {
        return std::make_shared<IllegalInstFault>(
            "vector_offload: vstart != 0 unsupported (phase 1)",
            machInst);
    }
    return NoFault;
}

bool
VecOffloadNonSplitInst::commitOffload(uint64_t seqNum,
    ThreadContext *tc) const
{
    if (tc->readMiscRegNoEffect(MISCREG_VSTART) != 0) {
        return true;
    }
    if (VecOffload::backend->arithQueueFull()) {
        return false;
    }
    VecOffloadRecord r = rec;
    refreshVConf(r, tc);
    if (scalarSrc == 1) {
        r.scalar = tc->getReg(intRegClass[machInst.rs1]);
    } else if (scalarSrc == 2) {
        r.scalar = tc->getReg(floatRegClass[machInst.rs1]);
    }
    VecOffload::backend->issueArith(r);
    return true;
}

std::string
VecOffloadNonSplitInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << "_voffload";
    return ss.str();
}

VecToScalarMacroInst::VecToScalarMacroInst(ExtMachInst _machInst,
    const char *mnem, bool fpDest)
    : RiscvMacroInst(mnem, _machInst, SimdMiscOp)
{
    this->flags[IsVector] = true;
    StaticInstPtr q = new VecToScalarQueryMicroInst(_machInst);
    StaticInstPtr c = new VecToScalarCollectMicroInst(_machInst, fpDest);
    this->microops.push_back(q);
    this->microops.push_back(c);
    this->microops.front()->setFirstMicroop();
    this->microops.back()->setLastMicroop();
}

std::string
VecToScalarMacroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << "_voffload";
    return ss.str();
}

VecToScalarQueryMicroInst::VecToScalarQueryMicroInst(ExtMachInst _machInst)
    : RiscvMicroInst("v2s_query", _machInst, SimdMiscOp)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));
    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec = buildVecOffloadRecord(_machInst);
    rec.opClass = VecOffloadToScalar;

    // renamed internal vector register: the collect micro sources it,
    // so it cannot issue before this micro executes (at the ROB head)
    setDestRegIdx(_numDestRegs++, vecRegClass[VecMemInternalReg0]);
    _numTypedDestRegs[VecRegClass]++;

    this->flags[IsVector] = true;
    this->flags[IsNonSpeculative] = true;
}

Fault
VecToScalarQueryMicroInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered");
    if (xc->readMiscReg(MISCREG_VSTART) != 0) {
        return std::make_shared<IllegalInstFault>(
            "vector_offload: vstart != 0 unsupported (phase 1)",
            machInst);
    }
    VecOffloadRecord q = rec;
    refreshVConf(q, xc->tcBase());
    VecOffload::backend->v2sIssueQuery(q);
    // dummy write to release the dependence chain
    vreg_t &d = *(vreg_t *)xc->getWritableRegOperand(this, 0);
    d.zero();
    return NoFault;
}

std::string
VecToScalarQueryMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic;
    return ss.str();
}

VecToScalarCollectMicroInst::VecToScalarCollectMicroInst(
    ExtMachInst _machInst, bool _fpDest)
    : RiscvMicroInst("v2s_collect", _machInst, SimdMiscOp),
      fpDest(_fpDest)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));
    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec = buildVecOffloadRecord(_machInst);

    setSrcRegIdx(_numSrcRegs++, vecRegClass[VecMemInternalReg0]);
    if (fpDest) {
        setDestRegIdx(_numDestRegs++, floatRegClass[_machInst.rd]);
        _numTypedDestRegs[FloatRegClass]++;
    } else {
        setDestRegIdx(_numDestRegs++, intRegClass[_machInst.rd]);
        _numTypedDestRegs[IntRegClass]++;
    }

    this->flags[IsVector] = true;
    this->flags[IsLoad] = true;
}

Fault
VecToScalarCollectMicroInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic("v2s_collect: timing-mode CPUs only (uses initiateAcc)");
}

Fault
VecToScalarCollectMicroInst::initiateAcc(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered");
    uint64_t va = VecOffload::backend->v2sLoadVAddr(xc->tcBase());
    const std::vector<bool> byte_enable(8, true);
    return xc->initiateMemRead(va, 8, Request::UNCACHEABLE, byte_enable);
}

Fault
VecToScalarCollectMicroInst::completeAcc(PacketPtr pkt, ExecContext *xc,
    trace::InstRecord *traceData) const
{
    // Minor completes disabled/suppressed accesses with a null packet;
    // fall back to reading the device word directly
    uint64_t val = pkt ? pkt->getLE<uint64_t>()
                       : VecOffload::backend->v2sPeekValue();
    if (fpDest) {
        if (rec.vsew == 0x2) {
            // NaN-box a 32-bit result in the 64-bit f-register
            val |= 0xffffffff00000000ULL;
        }
    } else if (rec.vfunct6 == 0x10 && (rec.vs1 == 16 || rec.vs1 == 17)) {
        // vcpop.m and vfirst.m share funct6 0x10 with vmv.x.s and are
        // told apart by the vs1 sub-opcode. Their results are COUNTS
        // and INDICES -- XLEN-wide by definition, not SEW-wide -- so
        // the sign extension below must not touch them. It silently
        // corrupted vcpop: a population count of 140 came back as
        // -116, but only once a single vcpop could see 128 or more set
        // bits, which needs a long vector. At VLEN=512 no chunk ever
        // held that many, so every short-vector test passed.
    } else {
        // vmv.x.s sign-extends the SEW-wide element into the x-register
        // (upstream reads vs2 through its *signed* typed view). The ACT
        // side is a datapath that returns raw element bits, so the
        // architectural scalar convention is applied here, where the
        // decoded SEW and gem5's own helpers already are.
        switch (rec.vsew) {
          case 0x0: val = sext<8>(val);  break;
          case 0x1: val = sext<16>(val); break;
          case 0x2: val = sext<32>(val); break;
          default:  break;  // SEW=64: already full width
        }
    }
    xc->setRegOperand(this, 0, val);
    if (traceData) {
        traceData->setData(fpDest ? floatRegClass : intRegClass, val);
    }
    return NoFault;
}

std::string
VecToScalarCollectMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic;
    return ss.str();
}

StaticInstPtr
makeVecOffloadNonSplit(ExtMachInst emi, const char *mnem, uint32_t elen,
                       uint32_t vlen)
{
    switch (emi.funct3) {
      case 0x2:  // OPMVV: vmv.x.s
        return new VecToScalarMacroInst(emi, mnem, false);
      case 0x1:  // OPFVV: vfmv.f.s
        return new VecToScalarMacroInst(emi, mnem, true);
      case 0x6:  // OPMVX: vmv.s.x
      case 0x5:  // OPFVF: vfmv.s.f
        return new VecOffloadNonSplitInst(emi, mnem);
      default:
        panic("makeVecOffloadNonSplit: unexpected funct3 %#x",
              (int)emi.funct3);
    }
}

StaticInstPtr
makeVecOffloadMaskLogical(ExtMachInst emi, const char *mnem)
{
    // vmand.mm / vmor.mm / vmnand.mm and friends: OPMVV, both sources
    // and the destination are mask registers, no scalar operand.
    return new VecOffloadNonSplitInst(emi, mnem);
}

VecOffloadMemMicroInst::VecOffloadMemMicroInst(ExtMachInst _machInst,
    const char *mnem, uint32_t _elen, uint32_t _vlen, bool _isStore,
    VecMemMode _mode)
    : VectorMicroInst(mnem, _machInst, SimdMiscOp,
                      _machInst.vl, 0, _elen, _vlen),
      isStore(_isStore), mode(_mode)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));
    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec = buildVecOffloadRecord(_machInst);
    // for mem ops funct3 carries the raw width bits; vd doubles as vs3
    // for stores
    rec.funct3 = _machInst.width;
    if (mode == VecMemMode::Mask) {
        rec.funct3 = 0;              // EEW=8
        rec.vm = 1;
        rec.vl = (_machInst.vl + 7) / 8;   // bytes, not elements
    } else if (mode == VecMemMode::Whole) {
        // A whole-register transfer is nf * VLENB bytes and ignores
        // vtype entirely, so describe it to the external unit as a
        // unit-stride byte move: EEW=8 (funct3 encoding 0), unmasked,
        // and vl in BYTES rather than elements.
        rec.funct3 = 0;
        rec.vm = 1;
        rec.vl = (_vlen / 8) * (_machInst.nf + 1);
    }
    rec.opClass = isStore ? VecOffloadStore : VecOffloadLoad;

    // declared for rename/dependence tracking; the architectural values
    // are read at the ROB head via the ThreadContext
    setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs1]);
    if (mode == VecMemMode::Strided) {
        setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs2]);
    }

    this->flags[IsVector] = true;
    this->flags[IsNonSpeculative] = true;
    // full serialization against scalar memory (phase-1 pessimism)
    this->flags[IsReadBarrier] = true;
    this->flags[IsWriteBarrier] = true;

    if (mode == VecMemMode::Fof) {
        // fault-only-first trims vl: modeled as an unconditional
        // control transfer carrying the new vconf (VlFFTrimVlMicroOp
        // pattern)
        this->flags[IsControl] = true;
        this->flags[IsIndirectControl] = true;
        this->flags[IsInteger] = true;
        this->flags[IsUncondControl] = true;
    }
}

bool
VecOffloadMemMicroInst::commitBlocked(uint64_t seqNum,
                                      ThreadContext *tc) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered");
    uint64_t base = tc->getReg(intRegClass[machInst.rs1]);
    uint64_t stride = (mode == VecMemMode::Strided)
        ? tc->getReg(intRegClass[machInst.rs2]) : 0;
    VecOffloadRecord m = rec;
    if (mode == VecMemMode::Mask) {
        refreshMaskVConf(m, tc);
    } else if (mode != VecMemMode::Whole) {
        refreshVConf(m, tc);
    }
    return VecOffload::backend->vecMemBlocked(seqNum, m, tc, base,
                                              stride, isStore, mode);
}

Fault
VecOffloadMemMicroInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    if (xc->readMiscReg(MISCREG_VSTART) != 0) {
        return std::make_shared<IllegalInstFault>(
            "vector_offload: vstart != 0 unsupported (phase 1)",
            machInst);
    }
    // the transfer completed while blocked at the ROB head
    if (mode == VecMemMode::Fof) {
        uint32_t new_vl = VecOffload::backend->consumeFofVl();
        auto tc = xc->tcBase();
        PCState pc;
        set(pc, xc->pcState());
        tc->setMiscReg(MISCREG_VSTART, 0);
        if (traceData) {
            traceData->setData(miscRegClass, RegVal(new_vl));
        }
        pc.vl(new_vl);
        pc.new_vconf(true);
        xc->pcState(pc);
    }
    return NoFault;
}

std::unique_ptr<PCStateBase>
VecOffloadMemMicroInst::branchTarget(ThreadContext *tc) const
{
    PCStateBase *pc_ptr = tc->pcState().clone();
    if (mode == VecMemMode::Fof && VecOffload::backend) {
        pc_ptr->as<PCState>().vl(VecOffload::backend->consumeFofVl());
    }
    return std::unique_ptr<PCStateBase>{pc_ptr};
}

std::string
VecOffloadMemMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << "_voffload";
    return ss.str();
}

VecMemIssueMicroInst::VecMemIssueMicroInst(ExtMachInst _machInst,
    const char *mnem, uint32_t _elen, uint32_t _vlen, bool _isStore,
    VecMemMode _mode)
    : VectorMicroInst(mnem, _machInst, SimdMiscOp,
                      _machInst.vl, 0, _elen, _vlen),
      isStore(_isStore), mode(_mode)
{
    setRegIdxArrays(
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::srcRegIdxArr),
        reinterpret_cast<RegIdArrayPtr>(
            &std::remove_pointer_t<decltype(this)>::destRegIdxArr));
    _numSrcRegs = 0;
    _numDestRegs = 0;

    rec = buildVecOffloadRecord(_machInst);
    rec.funct3 = _machInst.width;
    if (mode == VecMemMode::Mask) {
        rec.funct3 = 0;              // EEW=8
        rec.vm = 1;
        rec.vl = (_machInst.vl + 7) / 8;   // bytes, not elements
    } else if (mode == VecMemMode::Whole) {
        // A whole-register transfer is nf * VLENB bytes and ignores
        // vtype entirely, so describe it to the external unit as a
        // unit-stride byte move: EEW=8 (funct3 encoding 0), unmasked,
        // and vl in BYTES rather than elements.
        rec.funct3 = 0;
        rec.vm = 1;
        rec.vl = (_vlen / 8) * (_machInst.nf + 1);
    }
    rec.opClass = isStore ? VecOffloadStore : VecOffloadLoad;

    setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs1]);
    if (mode == VecMemMode::Strided) {
        setSrcRegIdx(_numSrcRegs++, intRegClass[_machInst.rs2]);
    }

    this->flags[IsVector] = true;
    // non-speculative: executes only at the commit point, in program
    // order, never from a wrong path, after older stores have drained.
    // It then retires immediately (fire-and-forget); the external
    // memory interlock orders the scalar stream against the transfer.
    this->flags[IsNonSpeculative] = true;
    // barrier flags: younger scalar memory ops must not execute before
    // this micro-op registers its interlock range at the commit point —
    // an out-of-order core would otherwise run a younger load before
    // the range exists and the interlock could never catch it. The
    // barrier lifts as soon as the micro-op issues (it does not wait
    // for the transfer), so the hand-off to the interlock is seamless.
    this->flags[IsReadBarrier] = true;
    this->flags[IsWriteBarrier] = true;
}

Fault
VecMemIssueMicroInst::execute(ExecContext *xc,
    trace::InstRecord *traceData) const
{
    panic_if(!VecOffload::backend,
             "vector_offload is enabled but no VecOffloadBackend is "
             "registered");
    if (xc->readMiscReg(MISCREG_VSTART) != 0) {
        return std::make_shared<IllegalInstFault>(
            "vector_offload: vstart != 0 unsupported (phase 1)",
            machInst);
    }
    uint64_t base = xc->getRegOperand(this, 0);
    uint64_t stride =
        (mode == VecMemMode::Strided) ? xc->getRegOperand(this, 1) : 0;
    VecOffloadRecord m = rec;
    if (mode == VecMemMode::Mask) {
        // A mask transfer carries ceil(vl/8) BYTES: refreshed, but as a
        // byte count. A plain refresh would install the element count
        // and transfer eight times too much.
        refreshMaskVConf(m, xc->tcBase());
    } else if (mode != VecMemMode::Whole) {
        // Whole-register transfers carry nf*VLENB bytes and ignore
        // vtype entirely, so there is nothing to refresh.
        refreshVConf(m, xc->tcBase());
    }
    VecOffload::backend->vecMemIssue(m, xc->tcBase(), base, stride,
                                     isStore, mode);
    return NoFault;
}

std::string
VecMemIssueMicroInst::generateDisassembly(Addr pc,
    const loader::SymbolTable *symtab) const
{
    std::stringstream ss;
    ss << mnemonic << "_voffload";
    return ss.str();
}

// Whole-register move (vmvNr.v): a raw copy of nf registers that
// ignores vl and vtype entirely. Same offload micro-op, tagged as a
// copy, with nf carried in the record so the external unit knows how
// much to move.
StaticInstPtr
makeVecOffloadCopyMicroop(ExtMachInst emi, const char *mnem, uint32_t elen,
                          uint32_t vlen)
{
    return new VecOffloadMicroInst(emi, mnem, elen, vlen);
}

std::vector<StaticInstPtr>
makeVecOffloadMemMicroops(ExtMachInst emi, const char *mnem, uint32_t elen,
                          uint32_t vlen, bool isStore, VecMemMode mode)
{
    if (emi.nf != 0) {
        // segment access: unit-stride, LMUL=1 only (phase-2 scope).
        // Check the encoding's mop bits: the segment constructor
        // templates are shared across unit/strided/indexed forms.
        panic_if(emi.mop != 0,
                 "%s: only unit-stride segment accesses are supported "
                 "with vector_offload", mnem);
        panic_if(emi.vtype8.vlmul != 0,
                 "%s: segment accesses require LMUL=1 with "
                 "vector_offload", mnem);
    }
    if (mode == VecMemMode::Fof || !VecOffload::decoupledMem) {
        // fault-only-first must know its trimmed vl before retiring;
        // blocking mode is also the A/B baseline
        return {new VecOffloadMemMicroInst(emi, mnem, elen, vlen,
                                           isStore, mode)};
    }
    return {new VecMemIssueMicroInst(emi, mnem, elen, vlen, isStore,
                                     mode)};
}

StaticInstPtr
makeVecOffloadMicroop(ExtMachInst emi, const char *mnem, uint32_t elen,
                      uint32_t vlen)
{
    return new VecOffloadMicroInst(emi, mnem, elen, vlen);
}

} // namespace RiscvISA
} // namespace gem5
