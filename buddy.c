#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "list.h"

#define MAX_ORDER 32
#define bool int
#define true 1
#define false 0

#ifdef DEBUG
#define pr_debug(fmt, ...) \
    printf("[DEBUG]%s: " fmt, __func__, ##__VA_ARGS__); \
    printf("\n")
#else
#define pr_debug(fmt, ...) 
#endif

/* Note that sizeof(struct freelist_entry) must be a power of 2 */
struct freelist_entry {
    struct list_head node;
    // TODO: more info can be added here
};

struct tiny_buddy_system {
    struct list_head freelists[MAX_ORDER];
    unsigned long allocated;
    unsigned long user_requested;
    unsigned long total;
};

static int next_power_of_two(int num)
{
    int limit = (1 << 30);
    if (num > limit) 
        return limit;
    
    if (!num)
        return 0;

    int tmp = num - 1;
    tmp |= (tmp >> 1);
    tmp |= (tmp >> 2);
    tmp |= (tmp >> 4);
    tmp |= (tmp >> 8);
    tmp |= (tmp >> 16);
    return (tmp < 0) ? 1 : tmp + 1;
}

static int prev_power_of_two(int num)
{
    int ret;

    ret = next_power_of_two(num);
    if (ret == num)
        return ret;

    return ret >> 1;
}

static int trailing_zeros(int num)
{
    if (!num)
        return sizeof(num) * 8;

    int cnt = 0;

    while (!(num & 1)) {
        num >>= 1;
        cnt++;
    }
    
    return cnt;
}

void tbs_init(struct tiny_buddy_system *buddy_sys, long start, long end)
{
    int order, max_order;
    long current_start;

    pr_debug("orignal start %p, end %p", start, end);
    start = (start + sizeof(struct freelist_entry) - 1) & ((~sizeof(struct freelist_entry)) + 1);
    end &= (~sizeof(struct freelist_entry)) + 1;
    assert(start <= end);
    pr_debug("aligned start %p, end %p", start, end);

    current_start = start;

    for (order = 0; order < MAX_ORDER; order++) 
        INIT_LIST_HEAD(&buddy_sys->freelists[order]);

    buddy_sys->user_requested = 0;
    buddy_sys->allocated = 0;

    while (current_start < end) {
        int remaining, size;
        struct freelist_entry *entry;
        
        remaining = prev_power_of_two(end - current_start);
        order = trailing_zeros(current_start);
        size = 1 << order;

        if (size > remaining) {
            size = remaining;
            order = trailing_zeros(remaining);
        }

        entry = (struct freelist_entry *)current_start;
        INIT_LIST_HEAD(&entry->node);
        list_add(&entry->node, &buddy_sys->freelists[order]);

        buddy_sys->total += size;
        current_start += size;
    }
    
}

void *tbs_alloc(struct tiny_buddy_system *buddy_sys, unsigned long size)
{
    int roundup_size, class, order;
    struct freelist_entry *target_entry;
    struct list_head *target_freelist;

    if (size < sizeof(struct freelist_entry)) {
        /* At least reserve some space for freelist entry */
        roundup_size = next_power_of_two(sizeof(struct freelist_entry));
    } else {
        roundup_size = next_power_of_two(size);
    }
    class = trailing_zeros(roundup_size);
    if (class >= MAX_ORDER) {
        printf("%s: Illegal request, size %lu", __func__, size);
        return NULL;
    }

    for (order = class; order < MAX_ORDER; order++) {
        if (list_empty(&buddy_sys->freelists[order]))
            continue;

        int split_order;
        for (split_order = order; split_order > class; split_order--) {
            struct freelist_entry *entry;
            struct freelist_entry *splited, *splited_buddy;
            struct list_head *next_freelist = &buddy_sys->freelists[split_order - 1];

            assert(!list_empty(&buddy_sys->freelists[split_order]));
            entry = list_first_entry(&buddy_sys->freelists[split_order], struct freelist_entry, node);
            pr_debug("entry %p, order %d", entry, order);
            list_del(&entry->node);
            if (!list_empty(&buddy_sys->freelists[split_order])) {
                assert(list_first_entry(&buddy_sys->freelists[split_order], struct freelist_entry, node) != entry);
            }
            splited = entry;
            splited_buddy = (struct freelist_entry *)((long)entry + (1 << (split_order - 1)));
            INIT_LIST_HEAD(&splited->node);
            INIT_LIST_HEAD(&splited_buddy->node);

            list_add(&splited->node, next_freelist);
            list_add(&splited_buddy->node, next_freelist);
        }

        break;
    }

    target_freelist = &buddy_sys->freelists[class];
    if (list_empty(target_freelist)) {
        printf("%s: OOM!\n", __func__);
        for (int i = 0; i < MAX_ORDER; i++) {
            if (!list_empty(&buddy_sys->freelists[i])) {
                printf("%s: order %d still free\n", __func__, i);
            }
        }
        return NULL;
    }

    target_entry = list_first_entry(target_freelist, struct freelist_entry, node);
    list_del(&target_entry->node);

    buddy_sys->allocated += roundup_size;
    buddy_sys->user_requested += size;

    pr_debug("allocated: %d, user requested: %d", buddy_sys->allocated, buddy_sys->user_requested);
    return target_entry;

}

void tbs_free(struct tiny_buddy_system *buddy_sys, void *ptr, unsigned long size)
{
    int class, roundup_size, order;
    struct freelist_entry *entry;

    if (size < sizeof(struct freelist_entry)) {
        /* At least reserve some space for freelist entry */
        roundup_size = next_power_of_two(sizeof(struct freelist_entry));
    } else {
        roundup_size = next_power_of_two(size);
    }
    class = trailing_zeros(roundup_size);
    assert(class < MAX_ORDER);

    entry = (struct freelist_entry *)(ptr);
    INIT_LIST_HEAD(&entry->node);
    list_add(&entry->node, &buddy_sys->freelists[class]);
    for (order = class; order < MAX_ORDER; order++) {
        struct freelist_entry *buddy = (struct freelist_entry *)((long)entry ^ (1 << order));
        struct freelist_entry *iter = NULL;
        bool buddy_is_free = false;

        list_for_each_entry(iter, &buddy_sys->freelists[order], node) 
            if (iter == buddy) {
                buddy_is_free = true;
                break;
            }

        if (buddy_is_free) {
            pr_debug("buddy is free, order %d", order);
            list_del(&entry->node);
            list_del(&buddy->node);
            if ((long)entry > (long)buddy) 
                entry = buddy;
            pr_debug("entry %p, order %d", entry, order);
            list_add(&entry->node, &buddy_sys->freelists[order + 1]);
        } else {
            break;
        }
    }

    buddy_sys->allocated -= roundup_size;
    buddy_sys->user_requested -= size;

    pr_debug("allocated: %d, user requested: %d", buddy_sys->allocated buddy_sys->user_requested);

}

struct tiny_buddy_system buddy_sys;

int main()
{
    long start, end;
    long len = 8 * 1024 * 1024;

    start = (long)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(start);
    end = start + len;
    tbs_init(&buddy_sys, start, end);
    char *dummy = tbs_alloc(&buddy_sys, 10);
    assert(dummy);
    printf("1\n");
    char *dummy2 = tbs_alloc(&buddy_sys, len / 2);
    assert(dummy2);
    printf("2\n");
    char *dummy3 = tbs_alloc(&buddy_sys, len / 4);
    assert(dummy3);
    printf("3\n");
    tbs_free(&buddy_sys, dummy, 10);
    int step = 1;
    for (long i = 0; i < len / 4; i += step) {
        char *dummy4 = tbs_alloc(&buddy_sys, step);
        if (!dummy4) {
            printf("i %ld, i * 16: %ld, total %ld\n", i, i * 16, len / 4);
            _exit(-1);
        }
    }
    printf("4\n");
}