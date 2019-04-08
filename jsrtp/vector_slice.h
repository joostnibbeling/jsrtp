#ifndef __VECTORSLICE_H__
#define __VECTORSLICE_H__
#include <vector>


template<class T>
class vector_slice
{
public:
	vector_slice(typename std::vector<T>::iterator begin, typename std::vector<T>::iterator end);
	vector_slice() = default;

	auto size();
	auto begin();
	auto end();
	decltype(auto) operator[](typename std::vector<T>::size_type idx);
private:
	typename std::vector<T>::iterator _begin;
	typename std::vector<T>::iterator _end;
	typename std::iterator_traits<typename std::vector<T>::iterator>::difference_type _size;
};

template<class T>
vector_slice<T>::vector_slice(typename std::vector<T>::iterator begin, typename std::vector<T>::iterator end)
{
	_begin = begin;
	_end = end;
	_size = std::distance(begin, end);
}

template<class T>
auto vector_slice<T>::size()
{
	return _size;
}

template<class T>
auto vector_slice<T>::begin()
{
	return _begin;
}

template<class T>
auto vector_slice<T>::end()
{
	return _end;
}

template<class T>
decltype(auto) vector_slice<T>::operator[](typename std::vector<T>::size_type idx)
{
	return *(_begin + idx);
}
#endif