#ifndef _HIDE_INFO_H_
#define _HIDE_INFO_H_

int init_hide_info(void);
void clear_hide_info(void);
int hide_info_add_filter(char *filter);

int add_hiden_path(char *parent, char *name);
void clear_hiden_path(char *parent, char *name);
int add_hiden_full_path(char *fullpath);

#endif

