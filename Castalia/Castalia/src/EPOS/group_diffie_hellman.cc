// EPOS Group Diffie-Hellman Component Implementation

#include <group_diffie_hellman.h>

__BEGIN_SYS

const unsigned char Group_Diffie_Hellman::_default_base_point_x[SECRET_SIZE] =
{
    (unsigned char)'\x86', (unsigned char)'\x5B', (unsigned char)'\x2C', (unsigned char)'\xA5',
    (unsigned char)'\x7C', (unsigned char)'\x60', (unsigned char)'\x28', (unsigned char)'\x0C',
    (unsigned char)'\x2D', (unsigned char)'\x9B', (unsigned char)'\x89', (unsigned char)'\x8B',
    (unsigned char)'\x52', (unsigned char)'\xF7', (unsigned char)'\x1F', (unsigned char)'\x16'
};

const unsigned char Group_Diffie_Hellman::_default_base_point_y[SECRET_SIZE] =
{
    (unsigned char)'\x83', (unsigned char)'\x7A', (unsigned char)'\xED', (unsigned char)'\xDD',
    (unsigned char)'\x92', (unsigned char)'\xA2', (unsigned char)'\x2D', (unsigned char)'\xC0',
    (unsigned char)'\x13', (unsigned char)'\xEB', (unsigned char)'\xAF', (unsigned char)'\x5B',
    (unsigned char)'\x39', (unsigned char)'\xC8', (unsigned char)'\x5A', (unsigned char)'\xCF'
};

Group_Diffie_Hellman::Group_Diffie_Hellman()
{
    new (&_base_point.x) Bignum(_default_base_point_x, SECRET_SIZE);
    new (&_base_point.y) Bignum(_default_base_point_y, SECRET_SIZE);
    _base_point.z = 1;
    _private_key.randomize();
}

Group_Diffie_Hellman::Round_Key Group_Diffie_Hellman::insert_key(Group_Diffie_Hellman::Round_Key round_key) const
{
	db<Group_Diffie_Hellman>(TRC) << "Diffie_Hellman::round_key(round=" << round_key << ",priv=" << _private_key << ")" << endl;

	round_key *= _private_key;

	db<Group_Diffie_Hellman>(INF) << "Diffie_Hellman: round key = " << round_key << endl;

	return round_key;
}

Group_Diffie_Hellman::Round_Key Group_Diffie_Hellman::insert_key() const
{
	db<Group_Diffie_Hellman>(TRC) << "Diffie_Hellman::round_key(round=" << _base_point << ",priv=" << _private_key << ")" << endl;

	Round_Key round_key = _base_point;
	round_key *= _private_key;	

	db<Group_Diffie_Hellman>(INF) << "Diffie_Hellman: round key = " << round_key << endl;

	return round_key;
}

Group_Diffie_Hellman::Round_Key Group_Diffie_Hellman::remove_key(Group_Diffie_Hellman::Round_Key round_key) const
{
	db<Group_Diffie_Hellman>(TRC) << "Diffie_Hellman::round_key(round=" << round_key << ",priv=" << _private_key << ")" << endl;

	Bignum::changeMod();
	Bignum inverted_private_key = _private_key;
	inverted_private_key.invert();
	Bignum::changeMod();
	round_key *= inverted_private_key;

	db<Group_Diffie_Hellman>(INF) << "Diffie_Hellman: round key = " << round_key << endl;

	return round_key;
}

__END_SYS
