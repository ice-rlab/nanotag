#include "handler.h"

static uint64_t global_tagged_fault_addr_aligned;
static uint8_t global_last_byte;
static uint8_t global_second_last_byte;
static uint64_t global_fault_pc;
static uint32_t global_fault_instruction;
static uint32_t global_breakpoint_instruction;
static bool breakpoint_handling_required = false;
static bool restore_second_last_byte = false;

static uint64_t counter = 0;

static uint64_t cached_page_start[MAX_CACHED_PAGE_NUM];
static int next_cached_page_index = 0;

static uint64_t threshold = DEFAULT_THRESHOLD;

static uint64_t tripwire_alloca_num = 0;
static uint64_t tripwire_access_num = 0;

void breakpoint_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *ucontext = (ucontext_t *)context;
    uint32_t* pc = (uint32_t *)ucontext->uc_mcontext.pc;
    uint32_t instruction = *pc;
    #ifdef DEBUG_PRINT
    printf("DEBUG: enter SIGTRAP handler. breakpoint_handling_required: %d; pc: %p; old_pc: 0x%lx; insn: 0x%x\n", breakpoint_handling_required, pc, global_fault_pc, instruction);
    #endif

    if (breakpoint_handling_required && (uint64_t)pc == global_fault_pc + 4 && instruction == BRK_INSTRUCTION) {
        asm volatile("stg %0, [%0]" : : "r" (global_tagged_fault_addr_aligned) : "memory");

        uint64_t __tagged_fault_addr_last_byte = global_tagged_fault_addr_aligned | 0xf;
        *((uint8_t*)__tagged_fault_addr_last_byte) = global_last_byte;

        if (restore_second_last_byte) {
            uint64_t __tagged_fault_addr_second_last_byte = global_tagged_fault_addr_aligned | 0xe;
            *((uint8_t*)__tagged_fault_addr_second_last_byte) = global_second_last_byte;
        }

        // restore the original instruction
        *pc = global_breakpoint_instruction;
        __builtin___clear_cache((char *)pc, (char *)(pc + 1));

        breakpoint_handling_required = false;
        return;
    } else {
        printf("Signal SIGTRAP. breakpoint_handling_required: %d; pc: %p; instruction: 0x%x; unhandled pc: 0x%lx; unhandled breakpoint instruction: 0x%x\n", breakpoint_handling_required, pc, instruction, global_fault_pc, global_breakpoint_instruction);
        _exit(EXIT_FAILURE);
    }
}

void mte_fault_handler(int sig, siginfo_t *info, void *context) {
    // tripwire_access_num++;

    int si_code = info->si_code;
    
    if (si_code == SEGV_MTESERR) {
        // Get the fault address and allocation tag
        uint64_t fault_addr = (uint64_t)(info->si_addr);
        ucontext_t *ucontext = (ucontext_t *)context;
        uint32_t* pc = (uint32_t *)ucontext->uc_mcontext.pc;
        uint32_t instruction = *pc;
        #ifdef DEBUG_PRINT
        printf("DEBUG: enter SIGSEGV handler. pc: %p; insn: 0x%x\n", pc, instruction);
        #endif

        if ((instruction & MASK_LOAD_STORE) != MATCH_LOAD_STORE) {
            printf("DEBUG: Shouldn't reach here. Handling a non-load/store instruction. PC: %p; instruction: 0x%x\n", pc, instruction);
            _exit(EXIT_FAILURE);
        }

        // PC relative addressing: any MTE tag mismatch indicate a true error
        if ((instruction & MASK_LOAD_LITERAL) == MATCH_LOAD_LITERAL) {
            printf("Signal SIGSEGV: sync tag check fault (fault address: %p; logical tag: 0x0)\n", info->si_addr);
            _exit(EXIT_FAILURE);
        }

        uint64_t __tagged_addr_mem;
        asm volatile("ldg %0, [%1]" : "=r" (__tagged_addr_mem) : "r" (fault_addr) : "memory");
        uint64_t allocation_tag = (__tagged_addr_mem >> 56) & 0xf;
        uint64_t tagged_fault_addr = fault_addr | (allocation_tag << 56); // Now you can use fault_addr to access the memory

        if (allocation_tag == 0) {
            #ifndef ENABLE_DETAILED_REPORT
            printf("Signal SIGSEGV: sync tag check fault (fault address: %p; allocation_tag: 0x0)\n", info->si_addr);
            #else
            printf("Tag Mismatch Fault (SYNC). PC: %p, Instruction: 0x%x, Fault Address: %p, Memory Tag: 0x0\n", 
                    pc, instruction, info->si_addr);
                        
            for (int i=0; i < 31; i++) {
                uint64_t __reg_val = ucontext->uc_mcontext.regs[i];
                printf("REG %d: 0x%lx\n", i, __reg_val);
            }

            // Require compile the sanitized program with `-g -rdynamic`
            // void *backtrace_buffer[MAX_FRAMES];
            // int num_frames = backtrace(backtrace_buffer, MAX_FRAMES);
            // backtrace_symbols_fd(backtrace_buffer, num_frames, STDERR_FILENO);
            #endif

            _exit(EXIT_FAILURE);
        } else {
            // All load/store instructions (except the PC-relative one) have the same base register indexing
            uint32_t __base_reg = (instruction >> 5) & 0x1f;
            uint64_t __base_reg_addr;
            if (__base_reg == 31) {
                __base_reg_addr = ucontext->uc_mcontext.sp;
            } else {
                __base_reg_addr = ucontext->uc_mcontext.regs[__base_reg];
            }
            #ifdef DEBUG_PRINT
            printf("DEBUG: base_reg_index: %d; base_reg_value: 0x%lx\n", __base_reg, __base_reg_addr);
            #endif

            // For register-offset load/store instructions, the tag used in access is determined by both the base register and the offset
            // Handle register-offset load/store instructions specially
            // xx11		0xx1xxxxxxxxx10	Load/store register (register offset) -> scale Rm depending on S (insn[12]), scale if set
            int64_t __register_offset = 0;
            bool __is_register_offset = false;
            if ((instruction & MASK_REGISTER_OFFSET_LOAD_STORE) == MATCH_REGISTER_OFFSET_LOAD_STORE) {
                __is_register_offset = true;
                uint32_t __rm = (instruction >> 16) & 0x1f;
                uint64_t __rm_val;
                if (__rm == 31) {
                    __rm_val = 0;
                } else {
                    __rm_val = ucontext->uc_mcontext.regs[__rm];
                }
                uint32_t __s = (instruction >> 12) & 0x1;
                
                uint64_t __scale;
                if (__s == 0x0) {
                    __scale = 0;
                } else {
                    uint32_t __size_bits = (instruction >> 30) & 0x3;
                    uint32_t __vr = (instruction >> 26) & 0x1;
                    uint32_t __opc = (instruction >> 22) & 0x3;

                    __scale = __size_bits;

                    bool __is_simd_fp = __vr;
                    if (__is_simd_fp && __size_bits == 0x0 && (__opc == 0x2 || __opc == 0x3)) {
                        __scale = 4;
                    }
                }

                uint32_t __option = (instruction >> 13) & 0x7;
                bool __is_unsigned = false;

                switch (__option) {
                    case 0x0:
                        // ExtendType_UXTB
                        __rm_val = __rm_val & 0xff;
                        __is_unsigned = true;
                        break;
                    case 0x1:
                        // ExtendType_UXTH
                        __rm_val = __rm_val & 0xffff;
                        __is_unsigned = true;
                        break;
                    case 0x2:
                        // ExtendType_UXTW
                        __rm_val = __rm_val & 0xffffffff;
                        __is_unsigned = true;
                        break;
                    case 0x3:
                        // ExtendType_UXTX
                        __is_unsigned = true;
                        break;
                    case 0x4:
                        // ExtendType_SXTB
                        __rm_val = (__rm_val & 0xff) | ((~(__rm_val & 0x80)) ? 0 : 0xffffffffffffff00);
                        break;
                    case 0x5:
                        // ExtendType_SXTH
                        __rm_val = (__rm_val & 0xffff) | ((~(__rm_val & 0x8000)) ? 0 : 0xffffffffffff0000);
                        break;
                    case 0x6:
                        // ExtendType_SXTW
                        __rm_val = (__rm_val & 0xffffffff) | ((~(__rm_val & 0x80000000)) ? 0 : 0xffff000000000000);
                        break;
                    case 0x7:
                        // ExtendType_SXTX
                        break;
                }

                if (__is_unsigned) {
                    __register_offset = (int64_t)(__rm_val << __scale);
                } else {
                    __register_offset = (int64_t)__rm_val << __scale;
                }
            }
            #ifdef DEBUG_PRINT
            printf("DEBUG: register_offset: 0x%lx; is_register_offset: %d\n", __register_offset, __is_register_offset);
            #endif

            uint64_t logical_tag = ((uint64_t)((int64_t)__base_reg_addr + __register_offset) >> 56) & 0xf;

            // Real allocation tag: the last byte of the padded granule
            uint64_t __last_byte_in_padded_granule = tagged_fault_addr | 0xf;
            uint64_t __last_byte = *((uint8_t*)__last_byte_in_padded_granule);
            uint64_t real_allocation_tag = __last_byte & 0xf;

            uint64_t tripwire_access_count = 0;
            uint8_t __updated_last_byte = __last_byte;
            
            if (allocation_tag == 0xf) {
                tripwire_access_count = (__last_byte >> 4) & 0xf;
                __updated_last_byte = (uint8_t)((__last_byte + 0x10) & 0xff);
                *((uint8_t*)__last_byte_in_padded_granule) = __updated_last_byte;
            } else {
                uint64_t __second_last_byte_in_padded_granule = tagged_fault_addr | 0xe;
                tripwire_access_count = *((uint8_t*)__second_last_byte_in_padded_granule);
                *((uint8_t*)__second_last_byte_in_padded_granule) = (uint8_t)((tripwire_access_count + 1) & 0xff);
            }

            if (logical_tag == allocation_tag) {
                printf("DEBUG: Shouldn't reach here. logical and allocation tags are the same. PC: %p; instruction: 0x%x; fault addr: 0x%lx\n", pc, instruction, fault_addr);
                printf("DEBUG: base_reg_index: %d; base_reg_value: 0x%lx\n", __base_reg, __base_reg_addr);
                printf("DEBUG: register_offset: 0x%lx; is_register_offset: %d\n", __register_offset, __is_register_offset);
                printf("DEBUG: logical tag: 0x%lx; allocation tag: 0x%lx; real allocation tag: 0x%lx\n", logical_tag, allocation_tag, real_allocation_tag);
                _exit(EXIT_FAILURE);
            }

            if (logical_tag == real_allocation_tag) {
                #ifdef DEBUG_TRACING
                uint64_t local_fault_addr_aligned = fault_addr & 0xfffffffffffffff0;
                printf("DEBUG_TRACING 0x%lx 0x%lx\n", allocation_tag, local_fault_addr_aligned);
                #endif
                // Only do intra-granule OOB checks for "handled" instructions
                // However, the original MTE checks for unhandled instructions in the last granule will still work as expected
                bool insn_is_load_store_pair = ((instruction & MASK_HANDLED_LOAD_STORE) == MATCH_HANDLED_LOAD_STORE_PAIR);
                bool insn_is_load_store_normal = ((instruction & MASK_HANDLED_LOAD_STORE) == MATCH_HANDLED_LOAD_STORE_NORMAL);
                
                // strcpy: 0xf8408402
                // strcmp: 0xf86a6803, 0xf9400002
                bool glibc_check_bypass = ((instruction == 0xf8408402) || (instruction == 0xf86a6803) || (instruction == 0xf9400002));

                if ((insn_is_load_store_pair || insn_is_load_store_normal) && !glibc_check_bypass) {
                    uint64_t __short_granule_start_byte = fault_addr & 0xf;
                    uint64_t __short_granule_allocation_size = allocation_tag;

                    if (__short_granule_start_byte >= __short_granule_allocation_size) {
                        #ifndef ENABLE_DETAILED_REPORT
                        printf("Signal SIGSEGV: sync tag check fault, short granule (fault address: %p; allocation_tag: 0x%lx; logical tag: 0x%lx; short granule size: %lu). PC: %p; instruction: 0x%x.\n", info->si_addr, real_allocation_tag, logical_tag, __short_granule_allocation_size, pc, instruction);
                        #else
                        printf("Tag Mismatch Fault (SYNC). PC: %p, Instruction: 0x%x, Fault Address: %p, Memory Tag: 0x%lx, Address Tag: 0x%lx\n", 
                               pc, instruction, info->si_addr, real_allocation_tag, logical_tag);
                        printf("Short Granule. Permitted Bytes: %lu, Short Granule Start Byte: %lu\n", __short_granule_allocation_size, __short_granule_start_byte);
                        
                        for (int i=0; i < 31; i++) {
                            uint64_t __reg_val = ucontext->uc_mcontext.regs[i];
                            printf("REG %d: 0x%lx\n", i, __reg_val);
                        }

                        // Require compile the sanitized program with `-g -rdynamic`
                        // void *backtrace_buffer[MAX_FRAMES];
                        // int num_frames = backtrace(backtrace_buffer, MAX_FRAMES);
                        // backtrace_symbols_fd(backtrace_buffer, num_frames, STDERR_FILENO);
                        #endif

                        #ifndef SHORT_GRANULE_PRINT_ONLY
                        _exit(EXIT_FAILURE);
                        #endif
                    } else {
                        uint64_t __size;
                        uint64_t __scale;
                        int64_t __offset = 0;
                        bool __is_post_indexed = false;

                        uint32_t __size_bits = (instruction >> 30) & 0x3;
                        uint32_t __vr = (instruction >> 26) & 0x1;
                        uint32_t __opc = (instruction >> 22) & 0x3;
                        bool __is_simd_fp_normal_load = false;

                        // Memory access size decoding
                        if (insn_is_load_store_normal) {
                            __size = 1 << __size_bits; // bytes
                            __scale = __size_bits;

                            bool __is_simd_fp = __vr;
                            // For atomic instructions, 128-bit atomic instructions are using a different encoding. Intra-granule OOB not supported for now.
                            if ((instruction & MASK_ATOMIC_LOAD_STORE) == MATCH_ATOMIC_LOAD_STORE) {
                                __is_simd_fp = false;
                            }

                            if (__is_simd_fp && __size_bits == 0x0 && (__opc == 0x2 || __opc == 0x3)) {
                                __size = 16;
                                __scale = 4;

                                if (__opc == 0x3) {
                                    __is_simd_fp_normal_load = true;
                                }
                            }
                        } else {
                            // handled load/store pair
                            bool __is_simd_fp = __vr;
                            if (__is_simd_fp) {
                                // SIMD/FP
                                switch (__size_bits) {
                                    case 0x0:
                                        __size = 8;
                                        __scale = 2;
                                        break;
                                    case 0x1:
                                        __size = 16;
                                        __scale = 3;
                                        break;
                                    case 0x2:
                                        __size = 32;
                                        __scale = 4;
                                        break;
                                    case 0x3:
                                        __size = 32;
                                        __scale = 4;
                                        break;
                                    default:
                                        printf("DEBUG: Shouldn't reach here. __is_simd_fp: %d; __size_bits: %d\n", __is_simd_fp, __size_bits);
                                        _exit(EXIT_FAILURE);
                                }
                            } else {
                                switch (__size_bits) {
                                    case 0x0:
                                        __size = 8;
                                        __scale = 2;
                                        break;
                                    case 0x1:
                                        __size = 8;
                                        __scale = 2;
                                        break;
                                    case 0x2:
                                        __size = 16;
                                        __scale = 3;
                                        break;
                                    case 0x3:
                                        __size = 16;
                                        __scale = 3;
                                        break;
                                    default:
                                        printf("DEBUG: Shouldn't reach here. __is_simd_fp: %d; __size_bits: %d\n", __is_simd_fp, __size_bits);
                                        _exit(EXIT_FAILURE);
                                }
                            }
                        }

                        // Offset calculation
                        if (insn_is_load_store_normal) {
                            // xx11		0xx0xxxxxxxxx00	Load/store register (unscaled immediate) -> imm9 = insn[20:12]
                            // xx11		0xx0xxxxxxxxx01	Load/store register (immediate post-indexed) -> unscaled immediate. imm9 = insn[20:12]
                            // xx11		0xx0xxxxxxxxx10	Load/store register (unprivileged) -> unscaled immediate. imm9 = insn[20:12]
                            // xx11		0xx0xxxxxxxxx11	Load/store register (immediate pre-indexed) -> unscaled immediate. imm9 = insn[20:12]
                            // xx11		0xx1xxxxxxxxx00	Atomic memory operations -> no offset
                            // xx11		0xx1xxxxxxxxx10	Load/store register (register offset) -> scale Rm depending on S (insn[12]), scale if set
                            // xx11		0xx1xxxxxxxxxx1	Load/store register (pac) -> not supported
                            // xx11		1xxxxxxxxxxxxxx	Load/store register (unsigned immediate) -> scaled immediate. imm12 = insn[21:10]
                            uint32_t __insn_24 = (instruction >> 24) & 0x1;
                            uint32_t __insn_21 = (instruction >> 21) & 0x1;
                            uint32_t __insn_11_10 = (instruction >> 10) & 0x3;

                            if (__insn_24 == 0x0) {
                                if (__insn_21 == 0x0) {
                                    if (__insn_11_10 == 0x1) {
                                        __is_post_indexed = true;
                                    } else {
                                        uint64_t imm9 = (instruction >> 12) & 0x1ff;
                                        if (imm9 & 0x100) {
                                            // negative offset, sign extend
                                            imm9 = imm9 | 0xfffffffffffffe00;
                                        }
                                        __offset = imm9;
                                    }
                                } else {
                                    if (__insn_11_10 == 0x2) {
                                        // Load/store register (register offset)
                                        if (__is_register_offset == false) {
                                            printf("DEBUG: Shouldn't reach here. __is_register_offset: %d\n", __is_register_offset);
                                            _exit(EXIT_FAILURE);
                                        }
                                        __offset = __register_offset;
                                    }
                                }
                            } else {
                                // Load/store register (unsigned immediate)
                                uint64_t imm12 = (instruction >> 10) & 0xfff;
                                __offset = (int64_t)(imm12 << __scale);
                            }
                        } else {
                            // handled load/store pair
                            // xx10		00xxxxxxxxxxxxx	Load/store no-allocate pair (offset)
                            // xx10		01xxxxxxxxxxxxx	Load/store register pair (post-indexed)
                            // xx10		10xxxxxxxxxxxxx	Load/store register pair (offset)
                            // xx10		11xxxxxxxxxxxxx	Load/store register pair (pre-indexed)

                            uint32_t __pair_index = (instruction >> 23) & 0x3;

                            if (__pair_index == 0x1) {
                                __is_post_indexed = true;
                            } else {
                                uint64_t imm7 = (instruction >> 15) & 0x7f;
                                if (imm7 & 0x40) {
                                    // negative offset, sign extend
                                    imm7 = imm7 | 0xffffffffffffff80;
                                }
                                __offset = (int64_t)imm7 << __scale;
                            }
                        }

                        #ifdef DEBUG_PRINT
                        printf("DEBUG: fault address: %p; allocation_tag: 0x%lx; logical tag: 0x%lx; short granule size: %lu; memory access size: %lu; offset: 0x%lx\n", info->si_addr, real_allocation_tag, logical_tag, __short_granule_allocation_size, __size, __offset);
                        #endif

                        if (__is_post_indexed && __offset != 0) {
                            printf("DEBUG: Shouldn't reach here. Post-index addressing handling mistake.\n");
                            _exit(EXIT_FAILURE);
                        }

                        // SIMD load instruction is not checked due to compatibility issues
                        if (__is_simd_fp_normal_load == false) {
                            uint64_t __base_plus_offset = (uint64_t)((int64_t)__base_reg_addr + __offset);
                            uint64_t __untagged_base_plus_offset = __base_plus_offset & 0x00ffffffffffffff;
                            uint64_t __size_beyond_fault_addr = __untagged_base_plus_offset + __size - fault_addr;
                            uint64_t __allowed_size_beyond_fault_addr = __short_granule_allocation_size - __short_granule_start_byte;
                            #ifdef DEBUG_PRINT
                            printf("DEBUG: size beyond fault address: %lu; allowed size beyond fault address: %lu\n", __size_beyond_fault_addr, __allowed_size_beyond_fault_addr);
                            #endif
                            
                            if (__size_beyond_fault_addr > __allowed_size_beyond_fault_addr) {
                                #ifndef ENABLE_DETAILED_REPORT
                                printf("Signal SIGSEGV: sync tag check fault, short granule (fault address: %p; allocation_tag: 0x%lx; logical tag: 0x%lx; short granule size: %lu; memory access size: %lu). PC: %p; instruction: 0x%x.\n", info->si_addr, real_allocation_tag, logical_tag, __short_granule_allocation_size, __size, pc, instruction);
                                #else
                                printf("Tag Mismatch Fault (SYNC). PC: %p, Instruction: 0x%x, Fault Address: %p, Memory Tag: 0x%lx, Address Tag: 0x%lx\n", 
                                        pc, instruction, info->si_addr, real_allocation_tag, logical_tag);
                                printf("Short Granule. Permitted Bytes: %lu, Attempted Bytes: %lu\n", __allowed_size_beyond_fault_addr, __size_beyond_fault_addr);
                                
                                for (int i=0; i < 31; i++) {
                                    uint64_t __reg_val = ucontext->uc_mcontext.regs[i];
                                    printf("REG %d: 0x%lx\n", i, __reg_val);
                                }

                                // Require compile the sanitized program with `-g -rdynamic`
                                // void *backtrace_buffer[MAX_FRAMES];
                                // int num_frames = backtrace(backtrace_buffer, MAX_FRAMES);
                                // backtrace_symbols_fd(backtrace_buffer, num_frames, STDERR_FILENO);
                                #endif
                                
                                #ifndef SHORT_GRANULE_PRINT_ONLY
                                _exit(EXIT_FAILURE);
                                #endif
                            }
                        } else {
                            // printf is not reentrant, thus it is not always safe to use printf in signal handlers
                            #ifdef ENABLE_WARNINGS
                            #ifdef DEBUG_PRINT
                            printf("Warning: 16-byte SIMD load instruction not handled for intra-granule OOB check due to compatibility issus.\n");
                            #else
                            write(STDOUT_FILENO, "Warning: 16-byte SIMD load instruction not handled for intra-granule OOB check due to compatibility issus.\n", 107);
                            #endif
                            #else
                            ;
                            #endif
                        }
                    }
                } else {
                    #ifdef ENABLE_WARNINGS
                    #ifdef DEBUG_PRINT
                    printf("Warning: current load/store instruction not supported (pc: %p, insn: 0x%x) for intra-granule OOB check.\n", pc, instruction);
                    #else
                    write(STDOUT_FILENO, "Warning: current load/store instruction not supported for intra-granule OOB check.\n", 83);
                    #endif
                    #else
                    ;
                    #endif
                }

                // Resume the execution: 1) set the correct tag; 2) set the breakpoint
                // 1) set the correct tag
                uint64_t __local_tagged_fault_addr_aligned = tagged_fault_addr & 0xfffffffffffffff0;
                uint64_t __bypass_fault_addr_aligned = ((fault_addr & 0x00ffffffffffffff) | (logical_tag << 56)) & 0xfffffffffffffff0;

                asm volatile("stg %0, [%0]" : : "r" (__bypass_fault_addr_aligned) : "memory");
                
                // 2) set the breakpoint
                uint64_t __local_fault_pc = (uint64_t)pc;
                uint32_t __local_breakpoint_instruction = *(pc + 1);
                #ifdef DEBUG_PRINT
                printf("DEBUG: breakpoint_instruction: 0x%x; tagged_fault_addr: 0x%lx; __bypass_fault_addr: 0x%lx\n", __local_breakpoint_instruction, __local_tagged_fault_addr_aligned, __bypass_fault_addr_aligned);
                #endif
                bool __is_setting_breakpoint = true;
                
                uint32_t __next_insn = *(pc + 1);

                if (__next_insn == RET_INSTRUCTION) {
                    __is_setting_breakpoint = false;
                }

                #ifndef DISABLE_ACCESS_THRESHOLD
                if (allocation_tag == 0xf) {
                    uint64_t __cur_count = tripwire_access_count + 1;
                    if ((__cur_count >= threshold) || (__cur_count >= 16)) {
                        __is_setting_breakpoint = false;
                    }
                } else {
                    if ((tripwire_access_count + 1) >= threshold) {
                        __is_setting_breakpoint = false;
                    }
                }
                #endif
                
                if (__is_setting_breakpoint) {
                    for (int j=0; j < 2; j++) {
                        int i;
                        uint64_t __page_start = (uint64_t)(pc+j) & ~(getpagesize() - 1);

                        for (i = next_cached_page_index - 1; i >= 0; i--) {
                            if (cached_page_start[i] == __page_start) {
                                break;
                            }
                        }
    
                        if (i == -1) {
                            #ifdef DEBUG_PRINT
                            printf("DEBUG: page not cached. page_start: 0x%lx; next_cached_page_index: %d\n", __page_start, next_cached_page_index);
                            #endif
                            cached_page_start[next_cached_page_index] = __page_start;
                            next_cached_page_index++;
    
                            if (next_cached_page_index >= MAX_CACHED_PAGE_NUM) {
                                next_cached_page_index = 0;
                            }
    
                            if (mprotect((void *)__page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                                perror("mprotect");
                                _exit(EXIT_FAILURE);
                            }
                        }
                    }

                    
                    *(pc + 1) = BRK_INSTRUCTION;
                    __builtin___clear_cache((char *)(pc + 1), (char *)(pc + 2));

                    if (breakpoint_handling_required == true) {
                        printf("DEBUG: Shouldn't reach here. Setting breakpoint: breakpoint_handling_required is already true.\n");
                        printf("DEBUG: pc: %p; instruction: 0x%x; breakpoint instruction: 0x%x. Unhandled pc: 0x%lx; unhandled fault instruction: 0x%x; unhandled breakpoint instruction: 0x%x\n", pc, instruction, __local_breakpoint_instruction, global_fault_pc, global_fault_instruction, global_breakpoint_instruction);
                        _exit(EXIT_FAILURE);
                    }

                    global_fault_pc = __local_fault_pc;
                    global_fault_instruction = instruction;
                    global_breakpoint_instruction = __local_breakpoint_instruction;
                    global_tagged_fault_addr_aligned = __local_tagged_fault_addr_aligned;
                    global_last_byte = __updated_last_byte;

                    breakpoint_handling_required = true;

                    if (allocation_tag == 0xf) {
                        restore_second_last_byte = false;
                    } else {
                        restore_second_last_byte = true;
                        global_second_last_byte = (uint8_t)((tripwire_access_count + 1) & 0xff);
                    }
                } else {
                    #ifdef ENABLE_WARNINGS
                    #ifdef DEBUG_PRINT
                    printf("Warning: next instruction is a branch/exception/system instruction, thus breakpoint not set. PC: %p; Next instruction: 0x%x\n", pc, global_breakpoint_instruction);
                    #else
                    write(STDOUT_FILENO, "Warning: next instruction is a branch/exception/system instruction, thus breakpoint not set.\n", 93);
                    #endif
                    #endif
                    if (breakpoint_handling_required == true) {
                        printf("DEBUG: Skipping breakpoint: breakpoint_handling_required is already true.\n");
                        printf("DEBUG: pc: %p; instruction: 0x%x; breakpoint instruction: 0x%x. Unhandled pc: 0x%lx; unhandled fault instruction: 0x%x; unhandled breakpoint instruction: 0x%x\n", pc, instruction, __local_breakpoint_instruction, global_fault_pc, global_fault_instruction, global_breakpoint_instruction);
                        _exit(EXIT_FAILURE);
                    }

                    breakpoint_handling_required = false;
                }

                return;
            } else {
                // Real tag mismatch, for all load/store instructions
                #ifndef ENABLE_DETAILED_REPORT
                printf("Signal SIGSEGV: sync tag check fault (fault address: %p; allocation_tag: 0x%lx; logical tag: 0x%lx). PC: %p; instruction: 0x%x.\n", info->si_addr, allocation_tag, logical_tag, pc, instruction);
                #else
                printf("Tag Mismatch Fault (SYNC). PC: %p, Instruction: 0x%x, Fault Address: %p, Memory Tag: 0x%lx, Address Tag: 0x%lx\n", 
                        pc, instruction, info->si_addr, allocation_tag, logical_tag);
                
                for (int i=0; i < 31; i++) {
                    uint64_t __reg_val = ucontext->uc_mcontext.regs[i];
                    printf("REG %d: 0x%lx\n", i, __reg_val);
                }

                // Require compile the sanitized program with `-g -rdynamic`
                // void *backtrace_buffer[MAX_FRAMES];
                // int num_frames = backtrace(backtrace_buffer, MAX_FRAMES);
                // backtrace_symbols_fd(backtrace_buffer, num_frames, STDERR_FILENO);
                #endif

                _exit(EXIT_FAILURE);
            }
        }
    } else {
        if (si_code == SEGV_MTEAERR) {
            printf("Signal SIGSEGV: async tag check fault\n");
            _exit(EXIT_FAILURE);
        } else {
            printf("Signal SIGSEGV: error code %d\n", si_code);
            _exit(EXIT_FAILURE);
        }
    }
}

#ifdef INTERCEPT_SIGNAL_HANDLER
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    static int (*real_sigaction)(int, const struct sigaction*, struct sigaction*) = NULL;
    if (!real_sigaction)
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");

    if ((signum == SIGSEGV) && (act != NULL) && (act->sa_sigaction != mte_fault_handler)) {
        write(STDOUT_FILENO, "Blocked attempt to overwrite SIGSEGV handler via sigaction()\n", 61);
        return 0;
    } else if ((signum == SIGTRAP) && (act->sa_sigaction != breakpoint_handler)) {
        write(STDOUT_FILENO, "Blocked attempt to overwrite SIGTRAP handler via sigaction()\n", 61);
        return 0;
    } else {
        return real_sigaction(signum, act, oldact);
    }
}

typedef void (*sighandler_t)(int);

sighandler_t signal(int signum, sighandler_t handler) {
    static sighandler_t (*real_signal)(int, sighandler_t) = NULL;
    if (!real_signal)
        real_signal = dlsym(RTLD_NEXT, "signal");

    if (signum == SIGSEGV) {
        write(STDOUT_FILENO, "Blocked attempt to overwrite SIGSEGV handler via signal()\n", 58);
        return 0;
    } else if (signum == SIGTRAP) {
        write(STDOUT_FILENO, "Blocked attempt to overwrite SIGTRAP handler via signal()\n", 58);
        return 0;
    } else {
        return real_signal(signum, handler);
    }
}
#endif

#ifdef FOPEN_INTERCEPT
FILE *fopen(const char *pathname, const char *mode) {
    char path[BUFFER_SIZE];
    strcpy(path, pathname);
    
    static FILE *(*real_fopen)(const char *, const char *) = NULL;

    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
        if (!real_fopen) {
            write(STDOUT_FILENO, "Error loading fopen()\n", 22);
            exit(1);
        }
    }
    write(STDOUT_FILENO, "Intercepted fopen()\n", 20);

    return real_fopen(path, mode);
}
#endif

__attribute__((constructor)) void init() {
    write(STDOUT_FILENO, "SETTING SIGNAL HANDLER\n", 23);

    const char *env_threshold = getenv("MTE_SANITIZER_THRESHOLD");
    if (env_threshold) {
        threshold = strtoull(env_threshold, NULL, 10);

        if (threshold > MAX_THRESHOLD) {
            printf("MTE_SANITIZER_THRESHOLD exceeds maximum value of %d.\n", MAX_THRESHOLD);
            exit(EXIT_FAILURE);
        }
        
        char buffer[BUFFER_SIZE];
        snprintf(buffer, BUFFER_SIZE, "MTE_SANITIZER_THRESHOLD set to %lu\n", threshold);
        write(STDOUT_FILENO, buffer, strlen(buffer));
    } else {
        write(STDOUT_FILENO, "MTE_SANITIZER_THRESHOLD not set. Using default value.\n", 55);
    }

    #ifdef DEBUG_PRINT
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;

    while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0) {
        write(STDOUT_FILENO, buffer, bytesRead);
    }
    if (bytesRead < 0) {
        perror("read");
    }
    close(fd);
    #endif

    #ifdef ENABLE_STACK_PROT_MTE
    #if RUN_ON_ANDROID == 0
    // In 64-bit systems, the stack is 8MB by default
    // Double check by running ulimit -s (size in KB)
    size_t size = 0x800000;

    void * stack = __builtin_frame_address(0);  // Get current stack pointer
    stack = (void *)((uint64_t)stack & ~(getpagesize() - 1));  // Align to page boundary

    mprotect(stack, size, PROT_READ | PROT_WRITE | PROT_MTE);
    #endif
    #endif

    struct sigaction sa_segv, sa_trap;

    // reference: https://man7.org/linux/man-pages/man2/sigaction.2.html
    // SA_SIGINFO: use sa_sigaction instead of sa_handler
    // SA_RESTART: making certain system calls restartable across signals
    sa_segv.sa_flags = SA_SIGINFO | SA_RESTART;
    sa_segv.sa_sigaction = mte_fault_handler;
    sigemptyset(&sa_segv.sa_mask);
    sigaddset(&sa_segv.sa_mask, SIGSEGV);
    sigaddset(&sa_segv.sa_mask, SIGTRAP);
    if (sigaction(SIGSEGV, &sa_segv, NULL) == -1) {
        perror("sigaction SIGSEGV");
        _exit(EXIT_FAILURE);
    }
    #ifdef DEBUG_PRINT
    printf("INIT: HANDLER ADDR %p\n", sa_segv.sa_handler);
    #endif

    sa_trap.sa_flags = SA_SIGINFO | SA_RESTART;
    sa_trap.sa_sigaction = breakpoint_handler;
    sigemptyset(&sa_trap.sa_mask);
    sigaddset(&sa_trap.sa_mask, SIGSEGV);
    sigaddset(&sa_trap.sa_mask, SIGTRAP);
    if (sigaction(SIGTRAP, &sa_trap, NULL) == -1) {
        perror("sigaction SIGTRAP");
        _exit(EXIT_FAILURE);
    }
}
