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

/**  Get a pointer to the structure which contains the list.
 * @param node   Pointer to a @c struct @ref list_head.
 * @param type   Type of the containing structure.
 * @param field	 Nam of the @c struct @ref list_head field inside @p type.
 * @returns      Pointer to the containing structure.
 */
#define list_entry(node, type, field) \
	(type*)((char*)(node) - offsetof(type, field))

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
	node->next = head->prev;
	node->prev = head;
	head->prev = node->prev->next = node;
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

#endif	/* list.h */
