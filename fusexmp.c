/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
   
  other modifications by Cameron Taylor and Steven Conflenti

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

//extra includes, macro for getting fuse info, functions to stop warnings
#include <stdlib.h>
#include <linux/limits.h>
#include "aes-crypt.h"
#define XMP_INFO ((info*)fuse_get_context() -> private_data)

//static int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
//static int xmp_getxattr(const char *path, const char *name, char *value, size_t size);
FILE *open_memstream(char **ptr, size_t *sizeloc);

//struct to hold the root and password
typedef struct{
	char* root;
	char* pass;
}info;

//extending the paths from the root for the mountpoint
static void xmp_extendPath(char filepath[PATH_MAX], const char *path){
    strcpy(filepath, XMP_INFO->root);
    strncat(filepath, path, PATH_MAX);		    
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = lstat(filepath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = access(filepath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = readlink(filepath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	(void) offset;
	(void) fi;

	dp = opendir(filepath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(filepath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(filepath, mode);
	else
		res = mknod(filepath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = mkdir(filepath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = unlink(filepath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = rmdir(filepath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = chmod(filepath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = lchown(filepath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = truncate(filepath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(filepath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = open(filepath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;
	FILE* fp;
	FILE* mfp;
	char* mval;
	size_t mlen;
	char xattrval[8];
	ssize_t xattrlen;
	int action = -1;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	(void) fi;
	
	//open file we want to read
	fp = fopen(filepath, "r");
	if(fp == NULL){
		return -errno;
	}
	
	//ready memstream
	mfp = open_memstream(&mval, &mlen);
	if(mfp == NULL){
		return -errno;
	}
	
	//check if file is encrypted
	xattrlen = getxattr(filepath, "user.encrypted", xattrval, 8);
	if (xattrlen != -1 && memcmp(xattrval, "true", 4) == 0){
		action = 0;
	}
	
	//decrypt file if encrypted, or copy if isn't encrypted
	do_crypt(fp, mfp, action, XMP_INFO -> pass);
	
	//wait for mfp to fully load, cleanup
	fflush(mfp);
	fseek(mfp, offset, SEEK_SET);
	fclose(fp);
	res = fread(buf, 1, size, mfp);
	fclose(mfp);
	if (res == -1)
		res = -errno;
	
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;
	FILE* fp;
	FILE* mfp;
	char* mval;
	size_t mlen;
	char xattrval[8];
	ssize_t xattrlen;
	int action = -1;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	(void) fi;
	
	//open file we want to write
	fp = fopen(filepath, "r");
	if(fp == NULL){
		return -errno;
	}
	
	//prep mstream
	mfp = open_memstream(&mval, &mlen);
	if(mfp == NULL){
		return -errno;
	}
	
	//check if file is encrypted
	xattrlen = getxattr(filepath, "user.encrypted", xattrval, 8);
	if (xattrlen != -1 && !memcmp(xattrval, "true", 4)){
		action = 0;
	}
	
	//unencrypt if encrypted, otherwise copy
	do_crypt(fp, mfp, action, XMP_INFO -> pass);
	fclose(fp);
	
	//find write area and load
	fseek(mfp, offset, SEEK_SET);
	res = fwrite(buf, 1, size, mfp);
	if (res == -1)
		res = -errno;
	fflush(mfp);
	
	//encrypt if we decrypted
	if(action == 0){
		action = 1;
	}
	
	fp = fopen(filepath, "w");
	fseek(mfp, 0, SEEK_SET);
	do_crypt(mfp, fp, action, XMP_INFO -> pass);
	
	//cleanup
	fclose(mfp);
	fclose(fp);
	
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);

	res = statvfs(filepath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
	int res;
	FILE* fp;
	FILE* mfp;
	char* mval;
	size_t mlen;
	
    (void) fi;
    (void) mode;

	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);
	
	//open new file
    fp = fopen(filepath, "w");
    if(fp == NULL){
		return -errno;
	}
	
	//prep mstream
	mfp = open_memstream(&mval, &mlen);
	if(mfp == NULL){
		return -errno;
	}
	
	//encrypt new file
	do_crypt(mfp, fp, 1, XMP_INFO -> pass);
	fclose(mfp);
	
	//set xattr flag to encrypted
	res = setxattr(filepath, "user.encrypted", "true", 4, 0);
	printf("%d\n", res);
	if(res){
		return -errno;
	}
	fclose(fp);
	
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

//#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);
	
	int res = lsetxattr(filepath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);
	
	int res = lgetxattr(filepath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);
	
	int res = llistxattr(filepath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char filepath[PATH_MAX];
	xmp_extendPath(filepath, path);
	
	int res = lremovexattr(filepath, name);
	if (res == -1)
		return -errno;
	return 0;
}
//#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	info *my_info;
	umask(0);
	
	if (argc < 4){
		printf("Usage: <encryption keyphrase> <mirror directory> <mount point>\n");
		return 1;
	}
	
	//create space to store the mirror directory and passphrase
    my_info = malloc(sizeof(info));
    if (my_info == NULL) {
		perror("Error in malloc in main.\n");
		abort();
    }

	//store path and pass
    my_info -> root = realpath(argv[argc-2], NULL);
    my_info -> pass = argv[argc-3];

	//reorganize argv to pass into fuse_main
    argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc = argc - 2;

	return fuse_main(argc, argv, &xmp_oper, my_info);
}
