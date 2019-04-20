#ifndef __ContainerSLICE_H__
#define __ContainerSLICE_H__

template<class Container>
class ContainerSlice
{
public:
	ContainerSlice(typename Container::iterator begin, typename Container::iterator end);
	ContainerSlice() = default;

	auto size();
	auto begin();
	auto end();
	decltype(auto) operator[](typename Container::size_type idx);
private:
	typename Container::iterator _begin;
	typename Container::iterator _end;
	typename std::iterator_traits<typename Container::iterator>::difference_type _size;
};

template<class Container>
ContainerSlice<Container>::ContainerSlice(typename Container::iterator begin, typename Container::iterator end)
{
	_begin = begin;
	_end = end;
	_size = std::distance(begin, end);
}

template<class Container>
auto ContainerSlice<Container>::size()
{
	return _size;
}

template<class Container>
auto ContainerSlice<Container>::begin()
{
	return _begin;
}

template<class Container>
auto ContainerSlice<Container>::end()
{
	return _end;
}

template<class Container>
decltype(auto) ContainerSlice<Container>::operator[](typename Container::size_type idx)
{
	return *(_begin + idx);
}
#endif