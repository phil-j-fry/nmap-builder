/* Synthetic excerpt shaped like nmap.cc's option table, for tools/extract-inventory.py tests. */
int parse_options(int argc, char **argv) {
  const char *k = "encoded";
  struct option long_options[] = {
    {"version", no_argument, 0, 'V'},
    {"datadir", required_argument, 0, 0},
    {"debug", optional_argument, 0, 'd'},
    {(char*)k, no_argument, 0, 0},
#ifndef NOLUA
    {"script", required_argument, 0, 0},
#endif
    {0, 0, 0, 0}
  };
  while ((arg = getopt_long_only(argc, argv, "46b:d::s::V", long_options, &option_index)) != EOF) {
  }
}
