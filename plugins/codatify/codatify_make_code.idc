#include <idc.idc>


// ###################################################################################
// Global variables

extern function_list;
extern function_list_size;
extern code_section;
extern data_section;


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


static make_code()
{
  auto addr;
  auto addr_2;
  auto eaddr;
  auto test;

  auto cc_code = 0;
  auto cc_func = 0;

  addr = code_section;

  while(get_segm_attr(addr, SEGATTR_PERM) & SEGPERM_EXEC) {

    eaddr = get_fchunk_attr(addr, FUNCATTR_END);
    addr_2 = get_next_fchunk(addr);

    if ( eaddr == BADADDR ) {
      test = add_func(addr, BADADDR);
      if (! test) {
        msg("[x] Can't make function for address 0x%lX\n", addr);
        test = create_insn(addr);
        if (test)
          cc_code = cc_code + 1;

        addr = next_addr(addr);
        continue;
      }

      cc_func = cc_func + 1;
      eaddr = get_fchunk_attr(addr, FUNCATTR_END);

    } else {

      if (addr_2 != eaddr) {
        addr = eaddr;

      } else {
        addr = addr_2;
      }
    }

  }

  msg("Create %d new functions and %d new code blocks\n", cc_func, cc_code);
}


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

  make_code();
}
