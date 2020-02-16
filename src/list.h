/** @internal @file list.h
 * @brief API for doubly-linked lists.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   libkdumpfile is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LIST_H
#define _LIST_H	1

#include <stddef.h>

/**  Cast a structure field out to the containing structure.
 * @param ptr    Pointer to the field.
 * @param type   Type of the container struct the field is part of.
 * @param field  Name of the field within the containing struct.
 */
#define container_of(ptr, type, field) \
	(type *)((char*)(ptr) - offsetof(type, field))

/**  Get a pointer to the structure which contains the list.
 * @param node   Pointer to a @c struct @ref list_head.
 * @param type   Type of the containing structure.
 * @param field	 Nam of the @c struct @ref list_head field inside @p type.
 * @returns      Pointer to the containing structure.
 */
#define list_entry(node, type, field) \
	container_of(node, type, field)

/**  A generic list head or node.
 * This structure is modelled after the Linux kernel list API.
 */
struct list_head {
	struct list_head *next;	/**< Pointer to the next node. */
	struct list_head *prev;	/**< Pointer to the previous node. */
};

/**  Initialize an empty list.
 * @param head  Uninitialized list head.
 */
static inline void
list_init(struct list_head *head)
{
	head->next = head->prev = head;
}

/**  Check if a list is empty.
 * @param head  List head to be checked.
 */
static inline int
list_empty(struct list_head *head)
{
	return head->next == head;
}

/**  Add a node to the list.
 * @param node  New node to be added.
 * @param head  List head (or preceding node).
 *
 * The new node is added after @p head.
 */
static inline void
list_add(struct list_head *node, struct list_head *head)
{
	node->next = head->next;
	node->prev = head;
	head->next = node->next->prev = node;
}

/**  Remove a node from the list.
 * @param node  Node to be deleted.
 */
static inline void
list_del(struct list_head *node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;
}

/**  Iterate over a list.
 * @param cur   List node to be used as the loop cursor.
 * @param head  List head.
 */
#define list_for_each(cur, head) \
        for (cur = (head)->next; cur != (head); cur = cur->next)

/**  Iterate over a list of a given type.
 * @param cur    Typed pointer to be used as the loop cursor.
 * @param head   List head.
 * @param field  Name of the @c struct @ref list_head field inside @p cur.
 */
#define list_for_each_entry(cur, head, field)				\
        for (cur = list_entry((head)->next, typeof(*(cur)), field);	\
	     &(cur)->field != (head);					\
	     cur = list_entry((cur)->field.next, typeof(*(cur)), field))

/**  A single-pointer list head to a double linked list.
 *
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful (hence the 'h' in its name).
 * You lose the ability to access the tail in O(1).
 *
 * This structure is modelled after the Linux kernel list API.
 */
struct hlist_head {
	struct hlist_node *first;
};

/**  Node of a double linked list with a single pointer list head.
 *
 * This structure is modelled after the Linux kernel list API.
 */
struct hlist_node {
	/** Pointer to the next node. */
	struct hlist_node *next;

	/** Pointer to the previous node's @c next pointer, or to
	 * the list head's @c first pointer. */
	struct hlist_node **pprev;
};

/**  Get a pointer to the structure which contains the hlist node.
 * @param node   Pointer to a @c struct @ref hlist_node.
 * @param type   Type of the containing structure.
 * @param field	 Nam of the @c struct @ref hlist_node field inside @p type.
 * @returns      Pointer to the containing structure.
 */
#define hlist_entry(node, type, field)				\
	({ typeof(node) ____ptr = (node);			\
	   ____ptr ? container_of(____ptr, type, field) : NULL;	\
	})

/**  Remove an element from a hlist.
 * @param node  Node to be deleted.
 */
static inline void hlist_del(struct hlist_node *node)
{
        struct hlist_node *next = node->next;
        struct hlist_node **pprev = node->pprev;

	*pprev = next;
        if (next)
                next->pprev = pprev;
}

/**  Add an element to the beginning of a hlist.
 * @param node  Node to be added
 * @param head  List head.
 */
static inline void
hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
        struct hlist_node *first = head->first;
        node->next = first;
        if (first)
                first->pprev = &node->next;
        head->first = node;
        node->pprev = &head->first;
}

/**  Iterate over a hlist.
 * @param cur   List node to be used as the loop cursor.
 * @param head  List head.
 */
#define hlist_for_each(cur, head) \
        for (cur = (head)->first; cur ; cur = cur->next)

/**  Iterate over a hlist of a given type.
 * @param cur    Typed pointer to be used as the loop cursor.
 * @param head   List head.
 * @param field  Name of the @c struct @ref hlist_node field inside @p cur.
 */
#define hlist_for_each_entry(cur, head, field)				\
        for (cur = hlist_entry((head)->first, typeof(*(cur)), field);	\
             cur;							\
             cur = hlist_entry((cur)->field.next, typeof(*(cur)), field))

#endif	/* list.h */
