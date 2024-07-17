// SPDX-License-Identifier: BSD-3-Clause
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"
#include "osmem.h"

#define META_SIZE sizeof(struct block_meta)
#define ALIGNMENT 8
#define MMAP_MAX 0x20000
#define MAX_PAGE 4096
#define CHUNK_ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

struct block_meta *InitList(void *init_heap, size_t size, int status)
{
	struct block_meta *init_block = (struct block_meta *)init_heap;

	if (init_block == MAP_FAILED)
		return NULL;

	init_block->size = size;
	init_block->status = status;
	init_block->prev = NULL;
	init_block->next = NULL;

	return init_block;
}

struct block_meta *extendBlock(
		struct block_meta *init_block, void *init_heap, size_t size, int status)
{
	struct block_meta *copy_init_block = init_block;
	struct block_meta *extend_block = (struct block_meta *)init_heap;

	for (; copy_init_block->next != NULL;)
		copy_init_block = copy_init_block->next;

	extend_block->size = size;
	extend_block->status = status;
	extend_block->prev = NULL;
	extend_block->next = NULL;

	copy_init_block->next = extend_block;
	extend_block->prev = copy_init_block;

	return init_block;
}

void coalesce(struct block_meta *init_block)
{
	if (init_block == NULL)
		return;

	struct block_meta *current_block = init_block;

	while (current_block->next != NULL) {
		if (current_block->status == 0 && current_block->next->status == 0) {
			current_block->size += current_block->next->size;
			current_block->next = current_block->next->next;

			if (current_block->next != NULL)
				current_block->next->prev = current_block;
		} else {
			current_block = current_block->next;
		}
	}
}

struct block_meta *init_block;
void *p;

void *Initializare(size_t size, size_t limit)
{
	if (init_block == NULL) {
		if (CHUNK_ALIGN(size) + META_SIZE > limit) {
			void *f = NULL;

			f = mmap(0, CHUNK_ALIGN(size) + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
			init_block = InitList(f, CHUNK_ALIGN(size) + META_SIZE, 2);
			f = f + META_SIZE;
			return f;
		}
			p = sbrk(0);
			p = sbrk(MMAP_MAX);
			init_block = InitList(p, MMAP_MAX + META_SIZE, 1);
			p = p + META_SIZE;
			return p;
	}
	return NULL;
}
// CHUNK_ALIGN e pentru padding
// functia de initializare a mallocului adica
// daca sizeul primit este mai mare decat META_SIZE se alloca cu mmap
// daca nu cu sbrk

void *Extindere(size_t size, size_t limit)
{
	if (CHUNK_ALIGN(size) + META_SIZE >= limit) {
		void *f = NULL;

		f = mmap(0, CHUNK_ALIGN(size) + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		init_block = extendBlock(init_block, f, CHUNK_ALIGN(size) + META_SIZE, 2);
		f = f + META_SIZE;
		return f;
	}
		struct block_meta *cp = init_block;

		for (; cp->next != NULL;)
			cp = cp->next;
		if (cp->status == 0 && cp->size < CHUNK_ALIGN(size) + META_SIZE) {
			void *q = cp;
			size_t newsize = CHUNK_ALIGN(size) + META_SIZE;
			size_t init_size = cp->size;

			cp->size = newsize;
			cp->status = 1;
			sbrk(newsize - init_size);
			return q + META_SIZE;
		}

		size_t newsize = CHUNK_ALIGN(size) + META_SIZE;

		p = sbrk(newsize);
		init_block = extendBlock(init_block, p, newsize, 1);
		p = p + META_SIZE;
		return p;
}

// la fel dar aici o sa verific daca ultimul nod are marime mai mica decat ce
// vreau sa pun ca sa pot exitnde heapul

void GasireBlocOptim(
		struct block_meta **get, struct block_meta *copy_init_block, size_t size)
{
	size_t MINIM = 10000000;

	for (; copy_init_block != NULL; copy_init_block = copy_init_block->next) {
		if (copy_init_block->status == 0) {
			if (copy_init_block->size == META_SIZE + CHUNK_ALIGN(size)) {
				*get = copy_init_block;
				return;
			}
			if (copy_init_block->size > META_SIZE + CHUNK_ALIGN(size)
					&& MINIM > copy_init_block->size) {
				MINIM = copy_init_block->size;
				*get = copy_init_block;
			}
		}
	}
}
// aici trebuie sa gasesc blocul optim pentru a putea da split

void Split(struct block_meta *get, size_t size)
{
	if (get->next == NULL) {
		void *r = get;
		struct block_meta *split_block = r + META_SIZE + CHUNK_ALIGN(size);

		split_block->size = get->size - CHUNK_ALIGN(size) - META_SIZE;
		split_block->status = 0;
		split_block->next = NULL;
		split_block->prev = NULL;

		get->size = CHUNK_ALIGN(size) + META_SIZE;
		get->status = 1;
		split_block->prev = get;
		get->next = split_block;
	} else if (get->next != NULL) {
		void *r = get;
		struct block_meta *split_block = r + META_SIZE + CHUNK_ALIGN(size);

		split_block->size = get->size - CHUNK_ALIGN(size) - META_SIZE;
		split_block->status = 0;
		split_block->next = NULL;
		split_block->prev = NULL;
		get->size = CHUNK_ALIGN(size) + META_SIZE;
		get->status = 1;

		struct block_meta *aux = get->next;

		split_block->prev = get;
		get->next = split_block;
		split_block->next = aux;
		aux->prev = split_block;
	}
}
// functia split se aplica atunci cand am un bloc mare si marimea primita
//	e mai mica atunci se da split

void *os_malloc_prepare(size_t size, size_t limit)
{ // aici o sa fac mallocul
	if (init_block == NULL)
		return Initializare(size, limit); // daca init e null se initializeaza

	struct block_meta *get = NULL;
	struct block_meta *copy_init_block = init_block;

	GasireBlocOptim(&get, copy_init_block, size); // gasesc blocul optim

	if (get != NULL) { // daca se gaseste se intra aici
		void *q = get;

		if (get->status == 0) { // verific daca are status 0 si o sa aiba
			if (get->size
					== META_SIZE + CHUNK_ALIGN(size)) { // dacca e egal il pun direct
				get->status = 1;

				if (get->next
						!= NULL) { // daca
					struct block_meta *cp
							= init_block; // se umple tot blocul caruia i s-a dat split
					int sum = 0; // atunci o sa verific daca s-a umplut PREA_HEAPUL si o
											 // sa il maresc
					for (; cp != get->next; cp = cp->next)
						sum += cp->size;
					if (sum == MMAP_MAX + META_SIZE) {
						get->status = 0;
						p = sbrk(META_SIZE + CHUNK_ALIGN(size));
						return p + META_SIZE;
					}
				}
				// aici la fel dar verific atunci cand PREA_HEAPUL nu e singurul bloc
				struct block_meta *cp = init_block;
				int sum = 0;

				for (; cp != NULL; cp = cp->next)
					sum += cp->size;

				if (sum == MMAP_MAX + META_SIZE)
					sbrk(META_SIZE);
			}
			if (get->size
					> META_SIZE + CHUNK_ALIGN(size)) { // daca e mai mare isi da split
				if (get->size - META_SIZE - CHUNK_ALIGN(size)
						> META_SIZE) // verific daca am loc aici
					Split(get, size); // daca am ii dau split daca nu il pun chiar daca
														// ramane spatiu
				else // pentru ca locul ala liber s-ar putea sa fie mai mic de
								 // META_SIZE
					get->status = 1;
			}
		}

		return q + META_SIZE;
	}

	if (get == NULL) { // daca nu am gasit extindem
		return Extindere(size, limit);
	}
	return NULL;
}

void *os_malloc(size_t size) // aici apelez malloc
{
	if (size <= 0)
		return NULL;

	return os_malloc_prepare(size, MMAP_MAX);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	// freeul functioneaza in felul urmator: daca statusul e 1 il fac 0 si las loc
	// liber pentru urmatoarele blocuri

	struct block_meta *extracted_block
			= (struct block_meta *)((char *)ptr - META_SIZE);

	if (extracted_block->status == 1) {
		extracted_block->status = 0;
		coalesce(init_block);
	}	else if (extracted_block->status == 2) {
	// daca e statusul 2 verific daca e doar un singur nod
	// daca e atunci il fac null inainte de a ii da munmap
		int ok = 0;

		if (init_block->next == NULL)
			ok = 1;

		size_t x = extracted_block->size;

		munmap(extracted_block, x);
		if (ok == 1)
			init_block = NULL;
	}
}
// calloc apeleaza malloc
void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	void *ptr = os_malloc_prepare(nmemb*size, MAX_PAGE);

	return memset(ptr, 0, nmemb*size);
}
// aici am facut doar preallocul si nopreallocate si cazurile in care
// se apeleaza malloc si in cazul in care size e 0
void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		struct block_meta *extracted_block = (struct block_meta *)((char *)ptr);

		extracted_block->status = 0;
		coalesce(init_block);
		return 0;
	}

	if (init_block == NULL || init_block->status == 2) {
		if (CHUNK_ALIGN(size) + META_SIZE > MMAP_MAX) {
			void *f = NULL;

			f = mmap(0, CHUNK_ALIGN(size) + META_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANON, -1, 0);
			init_block = InitList(f, CHUNK_ALIGN(size) + META_SIZE, 2);
			f = f + META_SIZE;
			return f;
		}
			p = sbrk(0);
			p = sbrk(MMAP_MAX);
			if (init_block->status == 2) {
				size_t s = init_block->size;

				init_block
						= extendBlock(init_block, p, CHUNK_ALIGN(size) + META_SIZE, 1);
				p = p + META_SIZE;
				struct block_meta *cp = init_block->next;
				struct block_meta *cp1 = init_block;

				cp->prev = NULL;
				cp->next = NULL;
				init_block = cp;

				munmap(cp1, s);
				return p;
			}
	}

	struct block_meta *get = ptr - META_SIZE;
	struct block_meta *copy_init_block = init_block;

	for (; copy_init_block != NULL; copy_init_block = copy_init_block->next) {
		if (copy_init_block == get) {
			if (CHUNK_ALIGN(size) + META_SIZE > MMAP_MAX) {
			} else {
				copy_init_block->size = CHUNK_ALIGN(size) + META_SIZE;
				void *f = get;

				return f + META_SIZE;
			}
		}
	}

	return NULL;
}
