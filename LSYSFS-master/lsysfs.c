#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_FILES 256
#define KEY_LENGTH 32
#define IV_LENGTH 16
#define MAX_CONTENT_SIZE 256

unsigned char keys[MAX_FILES][KEY_LENGTH];
unsigned char ivs[MAX_FILES][IV_LENGTH];

char dir_list[MAX_FILES][256];
int curr_dir_idx = -1;

char files_list[MAX_FILES][256];
int curr_file_idx = -1;

unsigned char files_content[MAX_FILES][MAX_CONTENT_SIZE];
int curr_file_content_idx = -1;

unsigned char file_keys[MAX_FILES][KEY_LENGTH];

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // 創建並初始化加密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，設置加密算法為AES-256-CBC，傳入密鑰和IV
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // 加密數據
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    // 完成加密操作
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    // 釋放加密上下文
    EVP_CIPHER_CTX_free(ctx);

    // print key
    printf("Encrypted data: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    // 創建並初始化解密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化解密操作，設置解密算法為AES-256-CBC，傳入密鑰和IV
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // 解密數據
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    // 完成解密操作
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // 釋放解密上下文
    EVP_CIPHER_CTX_free(ctx);

    // print key
    printf("Decrypted data: %s\n", plaintext);

    return plaintext_len;
}


void add_dir(const char *dir_name) {
    curr_dir_idx++;
    strcpy(dir_list[curr_dir_idx], dir_name);
}

int is_dir(const char *path) {
    path++; // Eliminating "/" in the path

    for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
        if (strcmp(path, dir_list[curr_idx]) == 0)
            return 1;

    return 0;
}

void add_file(const char *filename) {
    curr_file_idx++;
    strcpy(files_list[curr_file_idx], filename);

    curr_file_content_idx++;
    memset(files_content[curr_file_content_idx], 0, MAX_CONTENT_SIZE);

    // Generate random key and IV
    RAND_bytes(keys[curr_file_idx], KEY_LENGTH);
    RAND_bytes(ivs[curr_file_idx], IV_LENGTH);

    // print key
    printf("File: %s, Key: ", filename);
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", keys[curr_file_idx][i]);
    }
    printf("\n");
}

int is_file(const char *path) {
    path++; // Eliminating "/" in the path

    for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
        if (strcmp(path, files_list[curr_idx]) == 0)
            return 1;

    return 0;
}

int get_file_index(const char *path) {
    path++; // Eliminating "/" in the path

    for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
        if (strcmp(path, files_list[curr_idx]) == 0)
            return curr_idx;

    return -1;
}

void write_to_file( const char *path, const char *new_content )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 ) // No such file
		return;
		
	strcpy( files_content[ file_idx ], new_content ); 
}

// ... //

static int do_getattr(const char *path, struct stat *st) {
    st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
    st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
    st->st_atime = time(NULL); // The last "a"ccess of the file/directory is right now
    st->st_mtime = time(NULL); // The last "m"odification of the file/directory is right now

    if (strcmp(path, "/") == 0 || is_dir(path) == 1) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
    } else if (is_file(path) == 1) {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = MAX_CONTENT_SIZE;
    } else {
        return -ENOENT;
    }

    return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    filler(buffer, ".", NULL, 0); // Current Directory
    filler(buffer, "..", NULL, 0); // Parent Directory

    if (strcmp(path, "/") == 0) // If the user is trying to show the files/directories of the root directory show the following
    {
        for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++)
            filler(buffer, dir_list[curr_idx], NULL, 0);

        for (int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++)
            filler(buffer, files_list[curr_idx], NULL, 0);
    }

    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    int file_idx = get_file_index(path);

    if (file_idx == -1) {
        return -ENOENT;
    }

    if (fi->fh == 0) {
        return -EACCES; // 使用者没有提供key
    }

    unsigned char *key = (unsigned char *)fi->fh;

    unsigned char *content = files_content[file_idx];
    size_t content_len = strlen((char *)content);

    if (offset >= content_len) {
        return 0;
    }

    size_t read_size = size;
    if (offset + size > content_len) {
        read_size = content_len - offset;
    }

    unsigned char plaintext[MAX_CONTENT_SIZE];
    int plaintext_len = decrypt(content + offset, read_size, key, ivs[file_idx], plaintext);
    if (plaintext_len < 0) {
        return -EIO;
    }

    memcpy(buffer, plaintext, plaintext_len);
    return plaintext_len;
}

static int do_mkdir(const char *path, mode_t mode) {
    path++;
    add_dir(path);

    return 0;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
    path++;
    add_file(path);

    return 0;
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    int file_idx = get_file_index(path);

    if (file_idx == -1) {
        return -ENOENT;
    }

    if (fi->fh == 0) {
        return -EACCES; // 使用者没有提供key
    }

    unsigned char *key = (unsigned char *)fi->fh;

    size_t new_len = offset + size;
    if (new_len > MAX_CONTENT_SIZE) {
        return -EFBIG;
    }

    unsigned char *content = files_content[file_idx];
    size_t content_len = strlen((char *)content);

    if (offset > content_len) {
        memset(content + content_len, 0, offset - content_len);
        content_len = offset;
    }

    unsigned char ciphertext[MAX_CONTENT_SIZE];
    int ciphertext_len = encrypt((unsigned char *)buffer, size, key, ivs[file_idx], ciphertext);
    if (ciphertext_len < 0) {
        return -EIO;
    }

    memcpy(content + offset, ciphertext, ciphertext_len);

    if (offset + ciphertext_len > content_len) {
        content_len = offset + ciphertext_len;
    }

    return size;
}

static int do_utimens(const char *path, const struct timespec tv[2]) {
    int res = 0;
    (void)path;
    (void)tv;
    return res;
}

static int do_open(const char *path, struct fuse_file_info *fi) {
    int file_idx = get_file_index(path);

    if (file_idx == -1) {
        return -ENOENT;
    }

    unsigned char *key = keys[file_idx];
    if (key == NULL) {
        return -EACCES; // 使用者没有提供key
    }

    fi->fh = (uint64_t)key;

    return 0;
}


static int do_release(const char *path, struct fuse_file_info *fi) {
    fi->fh = 0;
    return 0;
}

static int do_unlink(const char *path) {
    int file_idx = get_file_index(path);

    if (file_idx == -1) {
        return -ENOENT;
    }

    // Remove the file from the files_list and reset its content
    memset(files_list[file_idx], 0, sizeof(files_list[file_idx]));
    memset(files_content[file_idx], 0, sizeof(files_content[file_idx]));

    // Shift all subsequent files in the array to fill the gap
    for (int i = file_idx; i < curr_file_idx; i++) {
        strcpy(files_list[i], files_list[i + 1]);
        memcpy(files_content[i], files_content[i + 1], sizeof(files_content[i]));
        memcpy(keys[i], keys[i + 1], sizeof(keys[i]));
        memcpy(ivs[i], ivs[i + 1], sizeof(ivs[i]));
    }

    curr_file_idx--;

    return 0;
}

static int do_rmdir(const char *path) {
    int dir_idx = -1;
    path++; // Eliminating "/" in the path

    for (int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++) {
        if (strcmp(path, dir_list[curr_idx]) == 0) {
            dir_idx = curr_idx;
            break;
        }
    }

    if (dir_idx == -1) {
        return -ENOENT;
    }

    // Remove the directory from the dir_list
    memset(dir_list[dir_idx], 0, sizeof(dir_list[dir_idx]));

    // Shift all subsequent directories in the array to fill the gap
    for (int i = dir_idx; i < curr_dir_idx; i++) {
        strcpy(dir_list[i], dir_list[i + 1]);
    }

    curr_dir_idx--;

    return 0;
}

static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .read = do_read,
    .mkdir = do_mkdir,
    .mknod = do_mknod,
    .write = do_write,
    .utimens = do_utimens,
    .open = do_open,
    .release = do_release,
    .unlink = do_unlink,
    .rmdir = do_rmdir,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &operations, NULL);
}

