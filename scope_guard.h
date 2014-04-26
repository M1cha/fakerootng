#ifndef SCOPE_GUARD_H
#define SCOPE_GUARD_H

template< typename Lambda >
class ScopeGuard
{
    bool committed; // not mutable
    Lambda rollbackLambda; 
    public:

        template <typename L>
        explicit ScopeGuard(L&& _l)
        // explicit, unless you want implicit conversions from *everything*
        : committed(false)
        , rollbackLambda(std::forward<L>(_l)) // avoid copying unless necessary
        {}

        template< typename AdquireLambda, typename L >
        ScopeGuard( AdquireLambda&& _al , L&& _l) : committed(false) , rollbackLambda(std::forward<L>(_l))
        {
            std::forward<AdquireLambda>(_al)(); // just in case the functor has &&-qualified operator()
        }

        // move constructor
        ScopeGuard(ScopeGuard&& that)
        : committed(that.committed)
        , rollbackLambda(std::move(that.rollbackLambda)) {
            that.committed = true;
        }

        ~ScopeGuard()
        {
            if (!committed)
                rollbackLambda(); // what if this throws?
        }
        void commit() { committed = true; } // no need for const
};

template< typename aLambda , typename rLambda>
ScopeGuard< rLambda > // return by value is the preferred C++11 way.
makeScopeGuard( aLambda&& _a , rLambda&& _r) // again perfect forwarding
{
    return ScopeGuard< rLambda >( std::forward<aLambda>(_a) , std::forward<rLambda>(_r )); // *** no longer UB, because we're returning by value
}

template<typename rLambda>
ScopeGuard< rLambda > makeScopeGuard(rLambda&& _r)
{
    return ScopeGuard< rLambda >( std::forward<rLambda>(_r ));
}

#endif // SCOPE_GUARD_H
