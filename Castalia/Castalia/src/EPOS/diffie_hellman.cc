// EPOS Elliptic Curve Diffie-Hellman (ECDH) Component Implementation

#include <diffie_hellman.h>

__BEGIN_SYS

// Class attributes
//TODO: base point is dependent of SECRET_SIZE
const unsigned char Diffie_Hellman::_default_base_point_x[SECRET_SIZE] =
{
    (unsigned char)'\x86', (unsigned char)'\x5B', (unsigned char)'\x2C', (unsigned char)'\xA5',
    (unsigned char)'\x7C', (unsigned char)'\x60', (unsigned char)'\x28', (unsigned char)'\x0C',
    (unsigned char)'\x2D', (unsigned char)'\x9B', (unsigned char)'\x89', (unsigned char)'\x8B',
    (unsigned char)'\x52', (unsigned char)'\xF7', (unsigned char)'\x1F', (unsigned char)'\x16'
};

const unsigned char Diffie_Hellman::_default_base_point_y[SECRET_SIZE] =
{
    (unsigned char)'\x83', (unsigned char)'\x7A', (unsigned char)'\xED', (unsigned char)'\xDD',
    (unsigned char)'\x92', (unsigned char)'\xA2', (unsigned char)'\x2D', (unsigned char)'\xC0',
    (unsigned char)'\x13', (unsigned char)'\xEB', (unsigned char)'\xAF', (unsigned char)'\x5B',
    (unsigned char)'\x39', (unsigned char)'\xC8', (unsigned char)'\x5A', (unsigned char)'\xCF'
};


// Class methods
Diffie_Hellman::Diffie_Hellman(const Elliptic_Curve_Point & base_point) : _base_point(base_point)
{
    generate_keypair();
}

Diffie_Hellman::Diffie_Hellman()
{
    new (&_base_point.x) Bignum(_default_base_point_x, SECRET_SIZE);
    new (&_base_point.y) Bignum(_default_base_point_y, SECRET_SIZE);
    _base_point.z = 1;
    generate_keypair();
}

Diffie_Hellman::Shared_Key Diffie_Hellman::shared_key(Elliptic_Curve_Point public_key)
{
    db<Diffie_Hellman>(TRC) << "Diffie_Hellman::shared_key(pub=" << public_key << ",priv=" << _private << ")" << endl;

    public_key *= _private;
    public_key.x ^= public_key.y;

    db<Diffie_Hellman>(INF) << "Diffie_Hellman: shared key = " << public_key.x << endl;
    return public_key.x;
}

__END_SYS
