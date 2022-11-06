#include <idc.idc>


// ###################################################################################
// Global variables

extern function_list;
extern function_list_size;
extern code_section;
extern data_section;

extern xrefs;


// ###################################################################################
// Functions


// find first code and data section/segment
static get_start_ea()

{
  auto addr = get_first_seg();
  code_section = BADADDR;
  data_section = BADADDR;
  auto attr_now;

  auto bcode = 1;
  auto bdata = 1;

  while((bcode | bdata ) && (addr != BADADDR))
  {
    attr_now = get_segm_attr(addr, SEGATTR_PERM);

    if (bcode)
      if (attr_now & SEGPERM_EXEC)
        code_section = addr;

    if (bdata)
      if (!(attr_now & SEGPERM_EXEC) && (attr_now & (SEGPERM_WRITE | SEGPERM_READ )))
        data_section = addr;

    addr = get_next_seg(addr);
    bcode = code_section == BADADDR;
    bdata = data_section == BADADDR;
  }

  return bcode | bdata;
}


static add_to_function_list(addr, eaddr)
{
  auto cc = function_list_size;
  function_list[cc] = object();
  function_list[cc].addr = addr;
  function_list[cc].eaddr = eaddr;
  function_list[cc].size = eaddr - addr;
  cc = cc + 1;
  function_list_size = cc;
}


static _get_func_list()
{
  auto addr;
  auto eaddr;

  for(addr=get_next_fchunk(code_section); addr != BADADDR; addr=get_next_fchunk(addr))
  {
    eaddr = get_fchunk_attr(addr, FUNCATTR_END);
    add_to_function_list(addr, eaddr);
  }
}



/*

static make_strings()
{
  auto addr;
  auto test;
  auto cc_str;

  addr = data_section;
  cc_str = 0;

  while(addr != BADADDR) {
    test = is_strlit(get_full_flags(addr));
    if (!test) {
      test = create_strlit(addr, 0);
      if (test) {
        cc_str = cc_str + 1;
      }
    }
    addr = next_addr(addr);


  }

}

static make_strings_utf8()
{
  // TODO
}


static find_f_xrefs()
{
  auto addr;
  auto xrefs = object();
  auto xref_now;

  xrefs.size = 0;
  xrefs.to_list = object();
  
  while (1)
  {
    xref_now = get_first_cref_to(cc);
    if (xref_now != BADADDR) {
      xrefs[xrefs.size] = object();
      xrefs[xrefs.size].to = cc;
      xrefs[xrefs.size].from = object();
      xrefs[xrefs.size].from[0] = xref_now;
      xrefs[xrefs.size].from.size = 1;
      
      xrefs.size = xrefs.size + 1;
    }

    cc = cc + 1;

    if (is_data(cc)) {
      break;
    }
  }

  return xrefs;
}
*/


/*

    - adjust data by ref, e.g.
        * go on data, save all xrefs
          > check if it is a string, if surpass xref, then all the other must be part of the same type
          > check if it is a pointer
          > check if it is a dword etc
        * disasm that line, find if dword/etc. is taken

static make_data()
{
  auto cc = data_section;
  auto ex;
  auto typ_now;
  auto is_64bit = is_bin_64bit();

  auto typ_tab = object();
  typ_tab[ FF_BYTE ] = 1;
  typ_tab[ FF_WORD ] = 2;
  typ_tab[ FF_DWORD ] = 4;
  typ_tab[ FF_QWORD ] = 8;
  typ_tab[ FF_TBYTE ] = 1;
  typ_tab[ FF_STRLIT ] = 0;
  typ_tab[ FF_STRUCT ] = 0;
  typ_tab[ FF_OWORD ] = 16;
  typ_tab[ FF_FLOAT ] = 4;
  typ_tab[ FF_DOUBLE ] = 4;
  typ_tab[ FF_PACKREAL ] = 0;
  typ_tab[ FF_ALIGN ] = 0;
  typ_tab[ FF_CUSTOM ] = 0;
  typ_tab[ FF_YWORD ] = 32;
  typ_tab[ FF_ZWORD ] = 64;

  if (is_64bit) {
    typ_tab[ FF_DOUBLE ] = 8;
  }

  while (1)
  {
    try {
      typ_now = typ_tab[ (! is_data(cc)) && (cc & DT_TYPE) ] ;
    } catch(ex) {
      typ_now = make_data_2(cc);
    }

    if
    cc = cc + typ_now;


   if (cc != BADADDR){
     break;
   }

  }
}


*/


// ###################################################################################
// Main


static main()
{
  auto function_list = object();
  auto function_list_size = 0;

  auto ret = get_start_ea();

  if(ret) {
    msg("[x] Can't find code, data section ..quit\n");
    return -1;
  }

  make_data();
}
