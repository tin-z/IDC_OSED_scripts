
// # author: Altin (tin-z)
// # description: Resolve a function table (string + functions) by adding comments to permit cross-ref on UI 

auto start_ea = 0xA1DA8;
auto end_ea = 0xA26F4 + 1;
auto rets = 0;
auto flags = 0;

while ( start_ea < end_ea ) {

  MakeDword(start_ea);
  rets = Dword(start_ea);

  if (rets != 0) {

    flags = get_flags(rets);

    if (flags != 0) {

      if ((flags & FF_ASCI) == FF_ASCI) {
        // resolve comment as string

        flags = GetStringType(rets);
        if (flags >= 0 && flags < 8) {
          MakeComm(start_ea, GetString(rets, BADADDR, flags));

        }

      } else {
        // resolve comment as function name
        MakeComm(start_ea, NameEx(BADADDR, rets));

      }
    }
  }

  start_ea = start_ea + 4;
}

msg("[+] Done\n");

