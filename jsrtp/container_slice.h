#ifndef __CONTAINERSLICE_H__
#define __CONTAINERSLICE_H__

template<class container>
class container_slice
{
public:
	container_slice(typename container::iterator begin, typename container::iterator end);
	container_slice() = default;

	auto size();
	auto begin();
	auto end();
	decltype(auto) operator[](typename container::size_type idx);
private:
	typename container::iterator _begin;
	typename container::iterator _end;
	typename std::iterator_traits<typename container::iterator>::difference_type _size;
};

template<class container>
container_slice<container>::container_slice(typename container::iterator begin, typename container::iterator end)
{
	_begin = begin;
	_end = end;
	_size = std::distance(begin, end);
}

template<class container>
auto container_slice<container>::size()
{
	return _size;
}

template<class container>
auto container_slice<container>::begin()
{
	return _begin;
}

template<class container>
auto container_slice<container>::end()
{
	return _end;
}

template<class container>
decltype(auto) container_slice<container>::operator[](typename container::size_type idx)
{
	return *(_begin + idx);
}
#endif