/**
   Author: Altin (tin-z)
   blog: https://tin-z.github.io/

 */


#include <idc.idc>


// Global variables
extern DBG;
extern tmp_folder;
extern tmp_output;
extern cc_tmp_output;
extern opts;
extern num_opts;

// CFG related global vars
extern visited_block;
extern visited_block_list;
extern visited_block_size;
extern sink_point;
extern source_point;
extern start_ea_func;
extern end_ea_func;

// Global enum variables
extern LOCAL_TARGET;
extern SHORT_TARGET;
extern FUNC_TARGET;
extern EXT_TARGET;


// ###################################################################################
// Utils

static msg_err(str) 
{ 
  msg("[x] %s\n",str); 
}

static msg_good(str)
{ 
  msg("[+] %s\n",str); 
}

static msg_wait(str) 
{ 
  msg("[-] %s\n",str); 
}

static msg_warn(str) 
{ 
  msg("[!] %s\n",str); 
}


/*
  Split string 's' using 's2' as the separator  
 */
static strSplit(s, s2)
{
	auto output = object();
	auto tmp_s = "";
	auto cc = 0;
	auto cc_2 = 0;
	auto len = strlen(s);

	for (cc=0; cc<len; cc=cc+1) {

		for(;cc<len;cc=cc+1) {
			if (s[cc] == s2) {
				break;
			}
			tmp_s = tmp_s + s[cc];
		}

		output[cc_2] = tmp_s;
		tmp_s = "";
		cc_2 = cc_2 + 1;

	}
	output.size = cc_2;
	return output;
}


/*
  Check if string 's' is in hex format
 */
static isHex(s)
{
	auto cc = 0;
	auto len = strlen(s);
	auto valid_char = "0123456789ABCDEFabcdef";
	auto cond = 1;
	for (cc=0; cc<len; cc=cc+1) {
		if ( strstr(valid_char, s[cc]) < 0) {
			cond = 0;
			break;
		}
	return cond;
	}
}


/*
  Pow function
 */
static pow(a, b) {
	auto rets = 1;
	auto cc = 0;
	for(cc=0; cc<=b; cc=cc+1) {
		rets = rets * a;
	}
	return rets;
}


/*
  Convert string 's' into long integer
 */
static strtol(s)
{
	auto cc = 0;
	auto len = strlen(s);
	auto ret_val = 0;
	auto char_tmp = 0;
	
	if (isHex(s)) {
		for(cc=0; cc<len; cc=cc+1) {

			char_tmp = ord(s[cc]);

			if (char_tmp > ord('9')) {
				if (char_tmp < ord('a')) {
					char_tmp = char_tmp - ord('A');
				} else {
					char_tmp = char_tmp - ord('a');
				}
				char_tmp = char_tmp + 10;
			} else {
				char_tmp = char_tmp - ord('0');
			}

			char_tmp = char_tmp << (4 * (len-cc-1));
			ret_val = ret_val + char_tmp;
		}
	}
	return ret_val;
}


/*
  Join strings from output list by 'sep' as the separator
 */
static join_str_list(sep, output) {
  auto ex;
  auto cc;
  auto output_str = "";
  auto output_tmp;

  for(cc=0; ; cc=cc+1) {
	  try {
      output_tmp = output[cc];
      output_str = output_str + output_tmp + sep;
		} catch (ex) {
      break;
    }
  }
  
  return output_str;
}


/*
  Save output list into file_path file
 */
static save_output_tmp(file_path)
{
  auto output = tmp_output;
  auto fp = fopen(file_path, "w");
  if (fp == 0) {
    msg_err(sprintf("Can't save output into file '%s'",file_path));
    return -1;
  } 
  auto ret = writestr(fp, join_str_list("\n", output));
  if (ret) {
    msg_err(sprintf("Can't save output into file '%s'",file_path));
    return -1;
  } else {
    msg_good(sprintf("Output saved into file '%s'",file_path));
    return 0;
  }
}


/*
  Read file_path content as a string
 */
static read_data_file(file_path)
{
  auto fp = fopen(file_path, "r");

  if (fp == 0) {
    msg_err(sprintf("Can't open file '%s'",file_path));
    return 0;
  } 

  auto ret = "";
  auto str_now;
  auto cc;

  for(cc=0;;cc = cc+1) {
    str_now = readstr(fp);
    if (str_now == BADADDR){
      break;
    }
    ret = ret + str_now;
  }
  
  if (!cc){
      msg_err(sprintf("Can't read file '%s' (possible reasons: empty-file, non-textual, permissions)",file_path));
      return 0;
  }

  return ret;
}


/*
  Do append operation on lists
 */
static AppendListSize(listA, listB)
{
  auto output = object();
  auto cc;

  output.size = listA.size + listB.size;

  for(cc=0; cc < listA.size; cc = cc + 1) {
    output[cc] = listA[cc];
  }
  for(cc=0; cc < listB.size; cc = cc + 1) {
    output[cc+listA.size] = listB[cc];
  }

  return output;
}


static is_bin_64bit() 
{
  auto info = get_inf_attr(INF_LFLAGS);
  return info & LFLG_64BIT;
}


// ###################################################################################
// Core

/*
  Return a filter object, which is used laster.
 */
static createFilter()
{
	auto filter = object();
	filter.startswith = "";
	filter.endswith = "";
	filter.in = "";
	return filter;
}


/*
  Compare the disassembled code (text format) 'disasm_line'
  using 'filter'. String comparisons are done with 'filter.startswith',
  'filter.endswith' and 'filter.in'.

  Note: IDC does not support standard regex. ::(
 */
static compareFilter(filter, disasm_line)
{
	auto valid_opcode = 1;
	auto s = "";
	auto idx = -1;

	s = filter.startswith;

	if (s != "" ) {
		idx = strstr(disasm_line, s);
		if (idx) {
			valid_opcode = 0;
		}
	}

	s = filter.endswith;
	if (s != "" ) {
		idx = strstr(disasm_line, s);
		if ((idx < 0) || (idx + strlen(s) != strlen(disasm_line))) {
			valid_opcode = 0;
		}
	}

	s = filter.in;
	if (s != "" ) {
		idx = strstr(disasm_line, s);
		if (idx < 0) {
			valid_opcode = 0;
		}
	}
	return valid_opcode;
}


/*
  Get the last address of a function
 */
static FindEndFunction(address)
{
  auto addr = address;

  auto attr_now = get_segm_attr(addr, SEGATTR_PERM);
  if ( !(attr_now & SEGPERM_EXEC) )
  {
    return addr;
  }

  auto name = Name(addr);
  auto eaddr = GetFunctionAttr(addr, FUNCATTR_END);

  if (eaddr == BADADDR)
  {
    msg("Can't find %s:\n", name);
    eaddr = 0;
  }
  return eaddr;
}


/*
  Save GLD graphfile
 */
static GenCFG(addr, eaddr)
{
	auto outfile = sprintf("%s\\cfg_%lX.gdl", tmp_folder, addr);
	auto title = sprintf("Title %lX-%lX", addr, eaddr);

	// ref, https://hex-rays.com/products/ida/support/idadoc/1253.shtml
	auto flags = CHART_NOLIBFUNCS | CHART_PRINT_NAMES;
	auto rets = gen_flow_graph(outfile, title, addr, eaddr, flags);
  return outfile;
}


/*
  Disassemble function with/without filtering opcode
*/
static DisasmFunc(addr, eaddr, filter)
{
	auto ret_array = object();
	auto cc = 0;
	auto size_now = 0;
	auto start = 0;
	auto valid_opcode = 0;

	for (start=addr; start<eaddr; start=start+size_now) {

		auto insn_mnem = print_insn_mnem(start);
		if (insn_mnem == "") {
			msg("[!] skipping 0x%lX\n", start);
  			continue;
		}

		auto disasm_line = generate_disasm_line(start, 0);
		valid_opcode = compareFilter(filter, disasm_line);

		if (valid_opcode && DBG) {
			msg("0x%lX: %s\n", start, disasm_line);
		}

		auto insn = decode_insn(start);
		size_now = insn.size;

		if ( valid_opcode ) {
			auto tmp_obj = object();
			tmp_obj.insn = insn;
                	tmp_obj.ea = start;
                	tmp_obj.size = size_now;
			tmp_obj.str = disasm_line;
			ret_array[cc] = tmp_obj;
			cc=cc+1;
		}
	}

	ret_array.size = cc;
	return ret_array;
}


/*
  Get the address which the COFI instruction points to jump and call
 */
static updateTargetCOFI(COFIobj, use_xref)
{
	auto target_str = "UNKNOWN";
	auto target = 0;

	auto rets = strSplit(COFIobj.str, " ");
	auto size = rets.size;

  if (use_xref) {
    target = get_first_fcref_from(COFIobj.ea);

  } else {

    if (size) {

      target_str = rets[size - 1];
      rets = strSplit(target_str, "_");
      size = rets.size;

      if (size) {
        target = strtol(rets[size - 1]);
      }
    }	

  }
	COFIobj.target = target;
	COFIobj.target_str = target_str;
}


/*
  Return COFI (change of flow instruction) instructions, e.g. jmp, call
 */
static GetCOFI(addr, eaddr, kind_of_COFI, only_local, only_short, only_sub, only_ext, use_xref)
{
	auto filter = createFilter();
	filter.startswith = kind_of_COFI;

	auto oldDBG = DBG;
	DBG = 0;
	auto insn_j = DisasmFunc(addr, eaddr, filter);
	DBG = oldDBG;

	auto output = object();
	auto cc_2 = 0;
	auto cc = 0;

	auto valid_opcode = 1;
	auto tmp_obj;
	auto exp;
	auto tmp_s;

	auto filter_local = createFilter();
	auto filter_short = createFilter();
	auto filter_sub = createFilter();
	filter_local.in = "loc_";
	filter_short.in = "short ";
	filter_sub.in = "sub_";
	
	for(cc=0; cc < insn_j.size; cc=cc+1, valid_opcode=1) {
		tmp_obj = insn_j[cc];
		auto disasm_line = tmp_obj.str;

    if ( ! use_xref ) {

      if (only_local) {
        valid_opcode = valid_opcode & compareFilter(filter_local, disasm_line);
      }
      if (only_short) {
        valid_opcode = valid_opcode & compareFilter(filter_short, disasm_line);
      }
      if (only_sub) {
        // in this case we override the other flags
        valid_opcode = compareFilter(filter_sub, disasm_line);
      }
      
      if (only_ext) {
        if ( (strstr(disasm_line, filter_local.in) >= 0) ||
             (strstr(disasm_line, filter_short.in) >= 0) ||
             (strstr(disasm_line, filter_sub.in) >= 0)
        ) {
          valid_opcode = 0;
        }
      }	
    }

		if (valid_opcode) {

      tmp_obj.typ = kind_of_COFI;
			updateTargetCOFI(tmp_obj, use_xref);

      // ignore loop and non-valid target call
      if ( (tmp_obj.target > 0) && !((tmp_obj.target >= addr) && (tmp_obj.target < eaddr)) ) {

			  output[cc_2] = tmp_obj;
			  cc_2 = cc_2 + 1;

			  if (DBG) {
				  msg("0x%lX: %s (target:%s 0x%lX)\n", tmp_obj.ea, disasm_line, tmp_obj.target_str, tmp_obj.target);
			  }

      }

		}
	}

	output.size = cc_2;
	return output;
}


/*
  Get jump instructions
 */
static GetJmps(addr, eaddr, only_local, only_short, only_sub, only_ext, use_xref)
{
	return GetCOFI(addr, eaddr, "j", only_local, only_short, only_sub, only_ext, use_xref);
}


/*
  Get call instructions
 */
static GetCalls(addr, eaddr, only_local, only_short, only_sub, only_ext, use_xref)
{
	return GetCOFI(addr, eaddr, "call", only_local, only_short, only_sub, only_ext, use_xref);
}



/*
  Traverse function block (fb) and update visited blocks.
  The scope is to build a interprocedural graph (no external calls) using DFS-algorithms
  
 */
static TraversePath(fb_from_addr, addr) {

	auto ex;
	auto fb;

  // Test if the address reached now was already visited,
  // then we need to updated .called array and its hit-counter
  //
	try {
		fb = visited_block[addr];

		try {

			ex = fb.called.hs[fb_from_addr.addr];
		} catch (ex) {

			fb.called.hs[fb_from_addr.addr] = 0;
			fb.called[fb.called.size] = fb_from_addr.addr;
			fb.called.size = fb.called.size + 1;
		}

		fb.called.hs[fb_from_addr.addr] = fb.called.hs[fb_from_addr.addr] + 1;
		return;

	} catch (ex) {
		// pass
	}

	auto eaddr = FindEndFunction(addr);
	if ( ! eaddr ) {
		msg("Can't find end addr of '0x%lX\n", addr);
		return;
	}

  // update visited_block global array 
  //
	fb = object();
	visited_block[addr] = fb;
	visited_block_list[visited_block_size] = addr;
	visited_block_size = visited_block_size + 1;

  // function block called by
  //  .called  : is an array with special attributes
  //      .size  : array size
  //      .hs    : hashmap <address, hit-counter>
  //
	fb.called = object();
	fb.called.size = 0;
	fb.called.hs = object();
	fb.called[fb.called.size] = fb_from_addr.addr;
	fb.called.size = fb.called.size + 1;
	fb.called.hs[fb_from_addr.addr] = 1;
	
  // function block calling
  //  .calling  : the same as .called
  //
	fb.calling = object();
	fb.calling.size = 0;
	fb.calling.hs = object();

  // save function block attributes
  //  .addr   : address
  //  .eaddr  : limit
  //  .fname  : function name
  //
	fb.addr = addr;
	fb.eaddr = eaddr;
	fb.fname = Name(addr);

  // if we reached the sink point, then return back
  // to the caller
  //
	if (addr == sink_point) {
		return;
	}

  start_ea_func = addr;
  end_ea_func = eaddr;

	auto calls = GetCalls(addr, eaddr, 0, 0, 1, 0, 1);
  auto jmps = GetJmps(addr, eaddr, 0, 0, 1, 0, 1);
  calls = AppendListSize(calls, jmps);

	auto cc = 0;
	for (cc=0; cc < calls.size; cc=cc+1) {

    try {
		auto call_i = calls[cc];
    } catch(ex) {
      //msg("HERE: Exception on addr 0x%lX cc:%d calls.size:%d jmps.size:%d\n", addr, cc, calls.size, jmps.size);
    }

		if (! call_i.target) {
			continue;
		}

    // update .calling array, then traverse the new address
    //
		try {
			ex = fb.calling.hs[call_i.target];
		} catch (ex) {
 			fb.calling.hs[call_i.target] = 0;
			fb.calling[fb.calling.size] = call_i.target;
			fb.calling.size = fb.calling.size + 1;
		}

 		fb.calling.hs[call_i.target] = fb.calling.hs[call_i.target] + 1;

		TraversePath(fb, call_i.target);
	}
}


/*
  Return function block info as string
 */
static FBToStr(fb, Id, space)
{
	auto head = sprintf("%sFB-%02d [%s][0x%lX : 0x%x]", space, Id, fb.fname, fb.addr, fb.eaddr);
	
	auto called = sprintf("%s \--> Called by: ", space);
	auto cc = 0;
	for(cc=0; cc < fb.called.size; cc=cc+1) {
		called = sprintf("%s 0x%lX,", called, fb.called[cc]);
	}
	called = called[:strlen(called)-1];

	auto calling = sprintf("%s \--> Calling to: ", space);
	cc = 0;
	for(cc=0; cc < fb.calling.size; cc=cc+1) {
		calling = sprintf("%s 0x%lX,", calling, fb.calling[cc]);
	}
	calling = calling[:strlen(calling)-1];

	return sprintf("%s\n%s\n%s\n", head, called, calling);
}


/*
  Print visited function blocks
 */
static PrintVisitedFB()
{
	auto cc;
	auto addr;
  auto sourceId;
  auto sinkId;

  tmp_output[cc_tmp_output] = "Visited function blocks (FB):";
	msg_good(tmp_output[cc_tmp_output]);
  cc_tmp_output = cc_tmp_output + 1;

	for(cc=0; cc < visited_block_size; cc=cc+1) {
		addr = visited_block_list[cc];
		if (addr == sink_point || addr == source_point ){
      if (addr == sink_point) {
        sinkId = cc;
      } else {
        sourceId = cc;
      }
			continue;
		}

    tmp_output[cc_tmp_output] = FBToStr(visited_block[addr], cc, " ");
  	msg(tmp_output[cc_tmp_output] + "\n");
    cc_tmp_output = cc_tmp_output + 1;
	}

  tmp_output[cc_tmp_output] = "";
	msg(tmp_output[cc_tmp_output]);
  cc_tmp_output = cc_tmp_output + 1;

  tmp_output[cc_tmp_output] = "Source point block:";
	msg_wait(tmp_output[cc_tmp_output]);
  cc_tmp_output = cc_tmp_output + 1;
  addr = source_point;
  tmp_output[cc_tmp_output] = FBToStr(visited_block[addr], sourceId, " ");
	msg(tmp_output[cc_tmp_output] + "\n");
  cc_tmp_output = cc_tmp_output + 1;

  tmp_output[cc_tmp_output] = "Sink point block:";
	msg_wait(tmp_output[cc_tmp_output]);
  cc_tmp_output = cc_tmp_output + 1;
  addr = sink_point;
  tmp_output[cc_tmp_output] = FBToStr(visited_block[addr], sinkId, " ");
	msg(tmp_output[cc_tmp_output] + "\n");
  cc_tmp_output = cc_tmp_output + 1;

  tmp_output[cc_tmp_output] = "Done Visited function blocks";
	msg_good(tmp_output[cc_tmp_output]);
  cc_tmp_output = cc_tmp_output + 1;
}


/*
  Generate a simple windbg python script able to trace source-sink points paths

  Note: traversing graph in backward starting from sink point
  until source point is reached
 */
static PrintPath_windbg(addr, prev_addr, nlevel)
{
	auto cc;

  // if we reached source point then print out the path
  //
	if (addr == source_point) {

		auto output = sprintf(" [0x%lX,", addr);
		for (cc=nlevel; cc>=0; cc=cc-1)	{
			output = sprintf("%s 0x%lX,", output, prev_addr[cc]);
		}
		output = output[:strlen(output)-1];
    output = output + "]";
		msg("[Path]: %s\n", output);

    tmp_output[cc_tmp_output] = output;
    cc_tmp_output = cc_tmp_output + 1;

		return;
	}
	
  // check if it was already visited
  for(cc=0; cc <= nlevel; cc=cc+1) {
    if ( addr == prev_addr[cc] ) {
      return;
    }
  }

  // update current node visited, and do DFS visiting
  // of the graph-similar we created by calling SetFB_CFG before
  //
	prev_addr[nlevel+1] = addr;

	auto bb = visited_block[addr];
	auto addr_tmp;

	for(cc=0; cc < bb.called.size; cc=cc+1) {
		addr_tmp = bb.called[cc];
		PrintPath_windbg(addr_tmp, prev_addr, nlevel+1);
	}

	return;
}


/*
  Print call to external modules from addr in a windbg breakpoint fashion
 */
static PrintExtCall_windbg(addr, eaddr)
{
	auto rets = GetCalls(addr, eaddr, 0, 0, 0, 1, 0);
	auto cc;
	auto output = "[ext calls]: ";

	for(cc=0; cc < rets.size; cc=cc+1) {
		output = sprintf("%s bp 0x%lX;", output, rets[cc].ea);
	}
	output = output[:strlen(output)-1];
	msg("%s\n", output);
}



// ###################################################################################
// Wrapper API

static get_current_sel()
{
  auto ea = get_screen_ea();
  auto sel = object();
  sel.addr = get_fchunk_attr(ea, FUNCATTR_START);
  sel.eaddr = get_fchunk_attr(ea, FUNCATTR_END);
  sel.size = sel.eaddr - sel.addr;
  sel.name = Name(sel.addr);
  return sel;
}

static ask_source_sink_points()
{
	visited_block = object();
	visited_block_list = object();
	visited_block_size = 0;
  source_point = ask_addr(BADADDR, "Insert the source point address");
  sink_point = ask_addr(BADADDR, "Insert the sink point address");
  
  if ((source_point == BADADDR) || (sink_point == BADADDR)) {
    msg_err("Wrong sink, source addresses");
    return -1;
  }
  return 0;
}


static do_gen_CFG()
{
  auto sel = get_current_sel();
  auto addr = sel.addr;
  auto eaddr = sel.eaddr;
  auto size = sel.size;
  auto name = sel.name;

	if (! eaddr) {
    msg_err("Bad function selected");
		return -1;
	}

  if ( DBG ) {
	   msg_wait(sprintf("Generating cfg of Function %s(0x%lX, 0x%lX) length:0x%lX", name, addr, eaddr, size));
  }

	auto outfile = GenCFG(addr, eaddr);
  msg_good(sprintf("CFG gdl file of function '%s' saved at '%s' location (open it using IDA's wingraph32.exe executable)\n", name, outfile));
  return 0;
}


static do_traverse(){
  tmp_output = object();
  cc_tmp_output = 0;

  auto ret = ask_source_sink_points();
  if ( ret ) {
    return -1;
  }

	auto fake_fb = object();
	fake_fb.addr = 0;
	ret = TraversePath(fake_fb, source_point);

  return 0;
}


static do_gen_CFG_func()
{
  auto ret = do_traverse();
  if ( ret ) {
    return;
  }
	PrintVisitedFB();

  auto file_path = sprintf("%s\\cfg_func.log", tmp_folder);
  save_output_tmp(file_path);
}


static do_print_CF_windbg()
{
  auto ret = do_traverse();
  if ( ret ) {
    return;
  }

	auto paths = object();

	PrintPath_windbg(sink_point, paths, -1);

  auto output = "In windbg invoke 'cfe_trace.py' as follows:";
  output = sprintf("%s\n.load pykd.pyd", output);
  output = sprintf(
    "%s\n!py %s\\cfe_trace.py --debug"
    " --source 0x%lX"
    " --sink 0x%lX"
    " --binary_name \"%s\""
    " --old_baddr 0x%lX" ,
    output, tmp_folder,
    source_point,
    sink_point,
    get_root_filename(),
    get_imagebase()
  );

  auto output_2 = " --chains \"[";
  auto cc;
  for(cc=0; cc < cc_tmp_output; cc=cc+1) {
    output_2 = sprintf("%s%s, ", output_2, tmp_output[cc]);
  }
	output_2 = output_2[:strlen(output_2)-2];
  output_2 = sprintf("%s]\"", output_2);

  output = sprintf("%s%s\n", output, output_2);
  msg(output);
}


static do_PrintExtCall_windbg()
{
  auto sel = get_current_sel();
  auto addr = sel.addr;
  auto eaddr = sel.eaddr;
  auto size = sel.size;
  auto name = sel.name;

	if (! eaddr) {
    msg_err("Bad function selected");
		return -1;
	}

	PrintExtCall_windbg(addr, eaddr);
}


// ###################################################################################
// Main

static helperMain(num_opts, opts){
	auto ver = "0.1";
	msg("############################################\n");
	msg("## ## ## ## ## ## ## ## ## ## ## ## ## ## ##\n");
	msg("#########   IDC-alleycat script (v%s)\n", ver);
	msg("\n");
  msg("#> list commands:\n");

  auto cc;
  for(cc=1; cc<num_opts; cc=cc+1) {
    msg("'%d' -> Invoke '%s'. Desc:%s\n", cc, opts[cc].fname, opts[cc].help);
  }

	msg("\n");
}


static initEnumVars()
{
  auto LOCAL_TARGET = 1;
  auto SHORT_TARGET = 2;
  auto FUNC_TARGET = 4;
  auto EXT_TARGET = 8;
}


static initMain(){
  DBG = ask_yn(0, "Do you want to enable debug mode? [default:No]");
  initEnumVars();
  auto opts = object();
  auto num_opts = 1;

	tmp_folder="C:\\Temp_ida";
  mkdir(tmp_folder, 0774);
  msg("Created temporary folder '%s'", tmp_folder);

  // create mapping hotkeys
  // #1
  opts[num_opts] = object();
  opts[num_opts].fname = "do_gen_CFG";
  opts[num_opts].help = 
    sprintf(
      "Gen and save the GLD graphfile of a function. Address is taken from the selector (output saved under folder '%s')", 
      tmp_folder
    );

  num_opts = num_opts + 1;

  // #2
  opts[num_opts] = object();
  opts[num_opts].fname = "do_PrintExtCall_windbg";
  opts[num_opts].help = "Print library calls from the current function address in a windbg breakpoint fashion";
  num_opts = num_opts + 1;

  // #3
  opts[num_opts] = object();
  opts[num_opts].fname = "do_gen_CFG_func";
  opts[num_opts].help = "Create function block (FB) graph, from source_point address to sink_point address, and then print visited FBs";
  num_opts = num_opts + 1;

  // #4
  opts[num_opts] = object();
  opts[num_opts].fname = "do_print_CF_windbg";
  opts[num_opts].help =
    sprintf(
      "Get possible paths from source to sink address, then generate a simple windbg python script able to trace them (output saved under folder '%s')",
      tmp_folder
    );

  num_opts = num_opts + 1;

  auto cc;
	for (cc=1; cc<num_opts; cc=cc+1) {
    AddHotkey(sprintf("%d",cc), opts[cc].fname);
  }

  helperMain(num_opts, opts);
}


static main()
{

  initMain();

  // doTests();

	msg("[+] Done!\n");
	return 0;
}


/*
static doTests()
{
	auto baddr = 0x401000;
	auto addr = baddr + 0x4590 - 0x1000;
	auto eaddr = FindEndFunction(addr);
	if (! eaddr) {
		return -1;
	}
	auto length = eaddr - addr;

	// TEST 1: Save CFG of a function
	auto s = sprintf("Generating cfg of Function (0x%lX, 0x%lX) length:0x%lX", addr, eaddr, length);
	print(s);
	GenCFG(addr, eaddr);

	// TEST 2: get jmp instructions
	auto ret2 = GetJmps(addr, eaddr, 1, 0, 0, 0, 0);

	// TEST 3: get call instructions
	auto ret3 = GetCalls(addr, eaddr, 0, 0, 1, 0, 0);

	// TEST 4: create function block graph, from source_point address to sink_point address
	auto sink_point = 0x407190;
	auto ret4 = SetFB_CFG(addr, sink_point);
	// print visited FBs
	PrintVisitedFB();

	// TEST 5: print possible path from source to sink in a windbg breakpoint fashion
	auto sink_point = 0x407190;
	auto ret5 = SetFB_CFG(addr, sink_point);
	auto paths = object();
	PrintPath_windbg(sink_point, paths, -1);


	// TEST 6: print external calls from source point
	PrintExtCall_windbg(addr, eaddr);
}
*/


