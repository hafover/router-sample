package utils

import (
	"sync"
)

type listElem[T any] struct {
	prev  *listElem[T]
	next  *listElem[T]
	value *T
}
type List[T any] struct {
	elem map[*T]*listElem[T]
	root listElem[T]
	mux  sync.Mutex
}

func NewList[T any]() *List[T] {
	l := &List[T]{}
	l.elem = make(map[*T]*listElem[T])
	l.root.prev, l.root.next = &l.root, &l.root
	return l
}

func (l *List[T]) Len() int { return len(l.elem) }

func (l *List[T]) Slice() []*T {
	s := make([]*T, 0, len(l.elem))
	for e := l.root.next; e != &l.root; e = e.next {
		s = append(s, e.value)
	}
	return s
}

func (l *List[T]) PushFront(v *T) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.insert(v, &l.root)
}

func (l *List[T]) PushBack(v *T) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.insert(v, l.root.prev)
}

func (l *List[T]) InsertBefore(v, at *T) bool {
	l.mux.Lock()
	defer l.mux.Unlock()
	if pos, ok := l.elem[at]; ok {
		l.insert(v, pos.prev)
		return true
	}
	return false
}

func (l *List[T]) InsertAfter(v, at *T) bool {
	l.mux.Lock()
	defer l.mux.Unlock()
	if pos, ok := l.elem[at]; ok {
		l.insert(v, pos)
		return true
	}
	return false
}

func (l *List[T]) Remove(v *T) {
	l.mux.Lock()
	defer l.mux.Unlock()
	if e, ok := l.elem[v]; ok {
		e.next.prev = e.prev
		e.prev.next = e.next
		delete(l.elem, v)
	}
}

func (l *List[T]) insert(v *T, at *listElem[T]) {
	if _, ok := l.elem[v]; ok {
		return
	}
	e := &listElem[T]{prev: at, next: at.next, value: v}
	at.next.prev = e
	at.next = e
	l.elem[v] = e
}
