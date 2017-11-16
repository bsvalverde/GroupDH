// EPOS Group Diffie-Hellman (GDH) Component Declarations

#ifndef __group_diffie_hellman_h
#define __group_diffie_hellman_h

#include <utility/bignum.h>
#include <elliptic_curve_point.h>
#include <cipher.h>

__BEGIN_SYS

class Group_Diffie_Hellman
{
public:
	static const unsigned int SECRET_SIZE = Cipher::KEY_SIZE;

private:
	typedef _UTIL::Bignum<SECRET_SIZE> Bignum;

public:
	typedef Elliptic_Curve_Point Round_Key;
	typedef Bignum Private_Key;
	typedef Bignum Shared_Key;
	typedef int Group_Id;

public:
	Group_Diffie_Hellman();

	Private_Key private_key() const { return _private_key; }

	Round_Key insert_key() const;
	Round_Key insert_key(Round_Key round_key) const;
	Round_Key remove_key(Round_Key round_key) const;

private:
	Private_Key _private_key;
	Elliptic_Curve_Point _base_point;
	static const unsigned char _default_base_point_x[SECRET_SIZE];
	static const unsigned char _default_base_point_y[SECRET_SIZE];
};

__END_SYS

#endif
