#include "PlatMemory.h"

LOG_CHANNEL(Platform.UtilMemory);

#ifdef GPCS4_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef WIN32_LEAN_AND_MEAN
#else
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#endif

namespace plat
{

#ifdef GPCS4_WINDOWS
	// GPCS4 flag to Windows flag
	inline uint32_t GetProtectFlag(VM_PROTECT_FLAG nOldFlag)
	{
		uint32_t nNewFlag = 0;
		do
		{
			if (nOldFlag & VMPF_NOACCESS)
			{
				nNewFlag = PAGE_NOACCESS;
				break;
			}

			if (nOldFlag & VMPF_CPU_READ)
			{
				nNewFlag = PAGE_READONLY;
			}

			if (nOldFlag & VMPF_CPU_WRITE)
			{
				nNewFlag = PAGE_READWRITE;
			}

			if (nOldFlag & VMPF_CPU_EXEC)
			{
				nNewFlag = PAGE_EXECUTE_READWRITE;
			}

		} while (false);
		return nNewFlag;
	}

	// Windows flag to GPCS4 flag
	inline VM_PROTECT_FLAG RecoverProtectFlag(uint32_t nOldFlag)
	{
		uint32_t nNewFlag = 0;
		do
		{
			if (nOldFlag & PAGE_NOACCESS)
			{
				nNewFlag = VMPF_NOACCESS;
				break;
			}

			if (nOldFlag & PAGE_READONLY)
			{
				nNewFlag |= VMPF_CPU_READ;
			}

			if (nOldFlag & PAGE_READWRITE)
			{
				nNewFlag |= VMPF_CPU_WRITE;
			}

			if ((nOldFlag & PAGE_EXECUTE) ||
				(nOldFlag & PAGE_EXECUTE_READ) ||
				(nOldFlag & PAGE_EXECUTE_READWRITE))
			{
				nNewFlag |= VMPF_CPU_EXEC;
			}

		} while (false);
		return static_cast<VM_PROTECT_FLAG>(nNewFlag);
	}

	VM_REGION_STATE GetRegionState(uint32_t nOldState)
	{
		VM_REGION_STATE nNewState = VMRS_FREE;
		if (nOldState == MEM_COMMIT)
		{
			nNewState = VMRS_COMMIT;
		}
		else if (nOldState == MEM_RESERVE)
		{
			nNewState = VMRS_RESERVE;
		}
		else if (nOldState == MEM_FREE)
		{
			nNewState = VMRS_FREE;
		}
		return nNewState;
	}

	inline uint32_t GetTypeFlag(VM_ALLOCATION_TYPE nOldFlag)
	{
		uint32_t nNewFlag = 0;
		do
		{
			if (nOldFlag & VMAT_RESERVE)
			{
				nNewFlag |= MEM_RESERVE;
			}

			if (nOldFlag & VMAT_COMMIT)
			{
				nNewFlag |= MEM_COMMIT;
			}

		} while (false);
		return nNewFlag;
	}

	void* VMAllocate(void* pAddress, size_t nSize, VM_ALLOCATION_TYPE nType, VM_PROTECT_FLAG nProtect)
	{
		DWORD dwType    = GetTypeFlag(nType);
		DWORD dwProtect = GetProtectFlag(nProtect);

		return VirtualAlloc(pAddress, nSize, dwType, dwProtect);
	}

	void* VMAllocateAlign(void* pAddress, size_t nSize, size_t nAlign, VM_ALLOCATION_TYPE nType, VM_PROTECT_FLAG nProtect)
	{

#ifdef GPCS4_DEBUG
		// This make it easier to find a function a Ida Pro.
		// When aligned with debugAlign, the loaded image address
		// is exactly the same as it in Ida Pro.
		// For example, without this debug align,
		// a function address may be 0x00000002b0240e21,
		// but with this align, you can search for sub_240e21
		// in Ida directly.
		const uint32_t debugAlign = 0x10000000;
		nAlign                    = debugAlign;
#endif

		void* pAlignedAddr = nullptr;
		do
		{
			DWORD     dwProtect = GetProtectFlag(nProtect);
			void*     pAddr     = VirtualAlloc(pAddress, nSize, MEM_RESERVE, dwProtect);
			uintptr_t pRefAddr  = util::align((uintptr_t)pAddr, nAlign);

			if (pAddr)
			{
				VirtualFree(pAddr, 0, MEM_RELEASE);
			}
			else
			{
				break;
			}

			do
			{
				pAlignedAddr = VirtualAlloc((void*)pRefAddr, nSize, MEM_RESERVE | MEM_COMMIT, dwProtect);
				pRefAddr += nAlign;
			} while (pAlignedAddr == nullptr);

		} while (false);

		return pAlignedAddr;
	}

	void VMFree(void* pAddress)
	{
		// MSDN:
		// If the dwFreeType parameter is MEM_RELEASE, this parameter(dwSize) must be 0(zero).
		// The function frees the entire region that is reserved in the initial allocation call to VirtualAlloc.
		VirtualFree(pAddress, 0, MEM_RELEASE);
	}

	bool VMProtect(void* pAddress, size_t nSize, VM_PROTECT_FLAG nNewProtect, VM_PROTECT_FLAG* pOldProtect)
	{
		DWORD dwNewProtect = GetProtectFlag(nNewProtect);
		DWORD dwOldProtect = 0;
		BOOL  bSuc         = VirtualProtect(pAddress, nSize, dwNewProtect, &dwOldProtect);
		if (pOldProtect)
		{
			*pOldProtect = RecoverProtectFlag(dwOldProtect);
		}
		return bSuc;
	}

	bool VMQuery(void* pAddress, MemoryInformation* pInfo)
	{
		bool ret = false;
		do
		{
			MEMORY_BASIC_INFORMATION mbi = {};
			if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0)
			{
				break;
			}

			pInfo->pRegionStart   = mbi.BaseAddress;
			pInfo->nRegionSize    = mbi.RegionSize;
			pInfo->nRegionState   = GetRegionState(mbi.State);
			pInfo->nRegionProtect = RecoverProtectFlag(mbi.Protect);

			ret = true;
		} while (false);
		return ret;
	}

	void* aligned_malloc(size_t align, size_t size)
	{
		_set_errno(0);
		void* ret = _aligned_malloc(size, align);
		if (errno == ENOMEM)
		{
			ret = nullptr;
		}
		return ret;
	}

	void aligned_free(void* ptr)
	{
		_aligned_free(ptr);
	}

#elif defined(GPCS4_LINUX)

	// GPCS4 flag to Linux flag
	inline int GetTypeFlag(VM_ALLOCATION_TYPE nOldFlag)
	{
		int nNewFlag = MAP_PRIVATE | MAP_ANONYMOUS; // Default flags

		do
		{
			if (nOldFlag & VMAT_RESERVE)
			{
				// In Linux, mmap always reserves the memory.
				// But we can use MAP_NORESERVE to indicate that the system should not reserve swap space.
				nNewFlag |= MAP_NORESERVE;
			}

			if (nOldFlag & VMAT_COMMIT)
			{
				// In Linux, mmap always commits the memory, so there's no equivalent flag.
				// We just keep the default flags.
			}

		} while (false);

		return nNewFlag;
	}

	// GPCS4 flag to Linux flag
	inline int GetProtectFlag(VM_PROTECT_FLAG nOldFlag)
	{
		int nNewFlag = 0;

		do
		{
			if (nOldFlag & VMPF_NOACCESS)
			{
				nNewFlag = PROT_NONE;
				break;
			}

			if (nOldFlag & VMPF_CPU_READ)
			{
				nNewFlag = PROT_READ;
			}

			if (nOldFlag & VMPF_CPU_WRITE)
			{
				nNewFlag |= PROT_WRITE;
			}

			if (nOldFlag & VMPF_CPU_EXEC)
			{
				nNewFlag |= PROT_EXEC;
			}

		} while (false);

		return nNewFlag;
	}

	void* VMAllocate(void* pAddress, size_t nSize, VM_ALLOCATION_TYPE nType, VM_PROTECT_FLAG nProtect)
	{
		int flags = GetTypeFlag(nType);
		int protection = GetProtectFlag(nProtect);

		return mmap(pAddress, nSize, protection, flags, -1, 0);
	}

	void* VMAllocateAlign(void* pAddress, size_t nSize, size_t nAlign, VM_ALLOCATION_TYPE nType, VM_PROTECT_FLAG nProtect)
	{
		// Linux's mmap automatically aligns to page size
		int protectFlag = GetProtectFlag(nProtect);
		int typeFlag = GetTypeFlag(nType);
		return mmap(pAddress, nSize, protectFlag, typeFlag, -1, 0);
	}

	void VMFree(void* pAddress)
	{
		munmap(pAddress, size);
	}

	bool VMProtect(void* pAddress, size_t nSize, VM_PROTECT_FLAG nNewProtect, VM_PROTECT_FLAG* pOldProtect)
	{
		int newProtectFlag = GetProtectFlag(nNewProtect);
		return mprotect(pAddress, nSize, newProtectFlag) == 0;
	}

	bool VMQuery(void* pAddress, MemoryInformation* pInfo)
	{
		FILE* mapsFile = fopen("/proc/self/maps", "r");
		if (!mapsFile)
		{
			return false;
		}

		uintptr_t addr = (uintptr_t)pAddress;
		uintptr_t start, end;
		while (fscanf(mapsFile, "%lx-%lx", &start, &end) == 2)
		{
			if (start <= addr && addr < end)
			{
				pInfo->pRegionStart = (void*)start;
				pInfo->nRegionSize = end - start;
				// You can fill in more details here if needed
				fclose(mapsFile);
				return true;
			}
		}

		fclose(mapsFile);
		return false;
	}

	void* aligned_malloc(size_t align, size_t size)
	{
		errno = 0;
		void* ret = nullptr;
		if (posix_memalign(&ret, align, size) != 0)
		{
			// posix_memalign will return nonzero on failure and set ret to NULL
			if (errno == ENOMEM)
			{
				ret = nullptr;
			}
		}
		return ret;
	}

	void aligned_free(void* ptr)
	{
		free(ptr);
	}

#endif  // GPCS4_WINDOWS

}  // namespace plat
