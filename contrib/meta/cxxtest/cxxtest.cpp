// Proves the pinned C++ toolchain and its sysroot are usable.
//
// `<string>` is the point of the include. libc++ lives in the SDK on macOS,
// so a standard header shows the sysroot was found.

// Every assertion is the test; `NDEBUG` would make `main` always succeed.
#ifdef NDEBUG
#error "NDEBUG erases the assertions this test is made of"
#endif

#include <cassert>
#include <string>

int main()
{
  static_assert(__cplusplus >= 202002L, "the toolchain is not compiling C++20");

  const std::string reported = "cheep cheep";
  assert(!reported.empty());
  assert(reported.find("cheep") == 0);

  return 0;
}
