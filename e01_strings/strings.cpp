// clang-format off
#include <windows.h>
#include <tlhelp32.h>
// clang-format on
#include <cinttypes>
#include <filesystem>
#include <iostream>
#include <utility>

// Written by cristeigabriel by the process of reverse engineering the program,
// then making some changes in parts where I believe that's the right approach.
// Hopefully I'm not breaking any EULA/law/... - I'm going to go out on a limb
// and not think about any of that.

static bool s_goingThroughDirectory = false;  // one or more
static bool s_foundAnyString = false;

struct Arguments {
  std::uint32_t m_minimumStringLength;  // length, not size
  std::uint64_t m_fileOffset;           // 0 - start
  std::uint64_t m_bytesToScan;          // 0 - all
  bool m_searchAscii;
  // remember to note correction
  bool m_searchWide;
  bool m_printOffset;
  bool m_recursiveSubdirectories;
};

namespace Util {
static HMODULE getLibrary(LPCWSTR library) {
  if (HMODULE libraryHandle = GetModuleHandleW(library)) return libraryHandle;

  return LoadLibraryW(library);
}

static BOOL isWow64Process() {
  BOOL wow64Process = FALSE;
  USHORT processMachine;
  USHORT nativeMachine;

  HMODULE kernel32 = getLibrary(L"kernel32");
  if (nullptr == kernel32) {
    __debugbreak();
    return FALSE;
  }

  HANDLE currentProcess = GetCurrentProcess();

  decltype(IsWow64Process2) *isWow64Process2Fn =
      (decltype(IsWow64Process2) *)GetProcAddress(kernel32, "IsWow64Process2");
  if (isWow64Process2Fn)
    wow64Process = (BOOL)(isWow64Process2Fn(currentProcess, &processMachine,
                                            &nativeMachine) &&
                          (processMachine != 0));
  else {
    decltype(IsWow64Process) *isWow64ProcessFn =
        (decltype(IsWow64Process) *)GetProcAddress(kernel32, "IsWow64Process");
    if (isWow64ProcessFn) isWow64ProcessFn(currentProcess, &wow64Process);
  }

  (void)nativeMachine;

  return wow64Process;
}

static void disableWow64FileSystemRedirection() {
  HMODULE kernel32 = getLibrary(L"kernel32");
  if (nullptr == kernel32) {
    __debugbreak();
    return;
  }

  decltype(Wow64DisableWow64FsRedirection) *wow64DisableWow64FsRedirectionFn =
      (decltype(Wow64DisableWow64FsRedirection) *)GetProcAddress(
          kernel32, "Wow64DisableWow64FsRedirection");

  PVOID old;
  if (wow64DisableWow64FsRedirectionFn) wow64DisableWow64FsRedirectionFn(&old);

  (void)old;
}

// call LocalFree on result
// we could have some template RAII class for this (and handles) which would
// automatically do above, but it feels rather offtopic
static LPWSTR getLastErrorStr() {
  LPWSTR buffer = nullptr;
  FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                 nullptr, GetLastError(), LANG_USER_DEFAULT, (LPWSTR)&buffer, 0,
                 nullptr);
  return buffer;
}
}  // namespace Util

// lateral divergence suggestions:
// - add mzpe mode
// - if there's a rdata section, add an option to only analyze that rdata
//      - problems: there's strings also in non-rdata sections, I remember
//      seeing some in
//      - data, before some pointers.
static void processFile(const std::filesystem::path &path,
                        const Arguments &arguments) {
  static constexpr DWORD pagesSize = 4096 * 16;  // 16 memory pages
  std::unique_ptr<BYTE[]> buffer(
      new BYTE[pagesSize]);  // we would rather this just be on heap for its
                             // significant size
  std::size_t pageNumber = 1;

  HANDLE file = CreateFileW(path.wstring().c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    LPWSTR buffer = Util::getLastErrorStr();
    std::wcout << L"Failed to open " << path << L", Reason: "
               << buffer;  // no endline because it's included by buffer
    LocalFree(buffer);
    return;
  }

  if (arguments.m_fileOffset != 0) {
    // distance to move is created by AND-ing the lower part from the bigger
    // number and then casting the result
    SetFilePointer(file, (LONG)(arguments.m_fileOffset & ~((DWORD)0)),
                   (PLONG)(((std::uint32_t *)&arguments.m_fileOffset) + 1),
                   FILE_BEGIN);
  }

  std::size_t numberOfBytesReadTotal = 0;
  DWORD numberOfBytesRead = 0;

  auto readMore = [&]() {
    DWORD actualBytesToRead = pagesSize;
    if (arguments.m_bytesToScan != 0 &&
        arguments.m_bytesToScan < (numberOfBytesReadTotal + pagesSize))
      actualBytesToRead =
          (DWORD)(arguments.m_bytesToScan -
                  numberOfBytesReadTotal);  // guaranteed to fit in DWORD
    BOOL result = ReadFile(file, buffer.get(), actualBytesToRead,
                           &numberOfBytesRead, nullptr);
    if (!result) {
      LPWSTR buffer = Util::getLastErrorStr();
      std::wcout << L"Failed to read " << path << L", Reason: "
                 << buffer;  // no endline because it's included by buffer
      LocalFree(buffer);
    }
    numberOfBytesReadTotal += numberOfBytesRead;
  };

  readMore();
  while (numberOfBytesRead > 0) {
    std::int32_t wideStringStart = -1, asciiStringStart = -1;
    for (auto i = 0u; i < numberOfBytesRead; i++) {
      // Here follows multiple problems that are present also in the strings.exe
      // in sysinternals suite

      // 1. does not support escape sequences ('\n', '\t', ...)
      // 2. does not support strings that could've been pretty much just held in
      // a non-wide string
      //    (as you may see, it uses isprint on the lower part of the wchar)
      //    if it doesn't do that, then it'll print a lot of trash

      auto printBuffer = [&]<typename T>(T str) {
        std::ptrdiff_t offset = pagesSize * pageNumber;
        if constexpr (std::is_same_v<T, LPSTR>)
          offset += asciiStringStart;
        else
          offset += wideStringStart;
        std::wstringstream ss;
        if (s_goingThroughDirectory) ss << path << L": ";
        if (arguments.m_printOffset)
          ss << std::hex << std::setw(8) << std::setfill(L'0') << offset
             << std::flush << L": ";
        ss << str << L'\n';
        std::wcout << ss.str();
      };

      if (arguments.m_searchWide && asciiStringStart == -1) {
        if (buffer[i] == 0 && isprint(buffer[i + 1])) {
          if (wideStringStart == -1) wideStringStart = i;

          i++;
          continue;
        }
        // if we started a string and got to the moment after we stopped
        else if (wideStringStart != -1) {
          if (DWORD length = (i - (DWORD)wideStringStart) / 2;
              length >= arguments.m_minimumStringLength) {
            // preallocate the string, and a null terminator.
            LPWSTR auxBuffer = (LPWSTR)LocalAlloc(LPTR, (length + 1) * 2);

            // copy string from buffer
            for (auto j = 0u; j < length; j++)
              auxBuffer[j] = (wchar_t)buffer[wideStringStart + (j * 2) + 1];

            // add null terminator
            auxBuffer[length] = 0;

            printBuffer(auxBuffer);
            LocalFree(auxBuffer);

            // notify app there's at least one string
            s_foundAnyString = true;
          }
          wideStringStart = -1;
        }
      }

      if (arguments.m_searchAscii && wideStringStart == -1) {
        if (isprint(buffer[i])) {
          if (asciiStringStart == -1) asciiStringStart = i;
        }
        // if we started a string and got to the moment after we stopped
        else if (asciiStringStart != -1) {
          if (DWORD length = i - (DWORD)asciiStringStart;
              length >= arguments.m_minimumStringLength) {
            // preallocate the string, and a null terminator.
            LPSTR auxBuffer = (LPSTR)LocalAlloc(LPTR, length + 1);

            // copy string from buffer
            for (auto j = 0u; j < length; j++)
              auxBuffer[j] = (char)buffer[asciiStringStart + j];

            // add null terminator
            auxBuffer[length] = 0;

            printBuffer(auxBuffer);
            LocalFree(auxBuffer);

            // notify app there's at least one string
            s_foundAnyString = true;
          }
          asciiStringStart = -1;
        }
      }
    }
    readMore();
    pageNumber++;
  }

  if (arguments.m_bytesToScan != 0 &&
      numberOfBytesReadTotal != arguments.m_bytesToScan)
    std::wcout << L"WARNING: Disparity between bytes to scan and total scanned "
                  L"bytes for "
               << path << L": " << numberOfBytesReadTotal << L" != "
               << arguments.m_bytesToScan << L'\n';

  CloseHandle(file);
}

static void forEachEntry(const std::filesystem::path &path, bool recursive,
                         auto &&fn) {
  if (recursive) {
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(path))
      fn(std::forward<decltype(entry)>(entry));
  } else {
    for (const auto &entry : std::filesystem::directory_iterator(path))
      fn(std::forward<decltype(entry)>(entry));
  }
}

static void processInput(const std::filesystem::path &path,
                         const Arguments &arguments) {
  if (!std::filesystem::exists(path)) {
    std::wcout << L"There's nothing at " << path << std::endl;
    exit(0);
  }

  if (std::filesystem::is_regular_file(path)) {
    processFile(path, arguments);
    return;
  }

  if (std::filesystem::is_directory(path)) {
    s_goingThroughDirectory = true;
    forEachEntry(path, arguments.m_recursiveSubdirectories,
                 [&](const auto &entry) {
                   if (entry.is_regular_file()) processFile(entry, arguments);
                 });
  }
}

int wmain(int argc, wchar_t **argv) {
  Arguments arguments = {.m_minimumStringLength = 5,
                         .m_fileOffset = 0,
                         .m_bytesToScan = 0,
                         .m_searchAscii = true,
                         .m_searchWide = true,
                         .m_printOffset = true,
                         .m_recursiveSubdirectories = true};

  // todo: parse above from command line

  if (Util::isWow64Process()) Util::disableWow64FileSystemRedirection();

  const std::filesystem::path path = argv[1];
  processInput(path, arguments);

  if (!s_foundAnyString)
    std::wcout << L"Could not find any string in " << path << std::endl;

  return 1;
}
