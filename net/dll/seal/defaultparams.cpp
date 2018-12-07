// SEALDll
#include "stdafx.h"
#include "defaultparams.h"
#include "utilities.h"

// SEAL
#include "seal/defaultparams.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL DefParams_CoeffModulus128(uint64_t polyModulusDegree, uint64_t* length, void** coeffs)
{
    IfNullRet(length, E_POINTER);

    vector<SmallModulus> coeffs128;
    try
    {
        coeffs128 = coeff_modulus_128(polyModulusDegree);
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    BuildCoeffPointers(coeffs128, length, coeffs);
    return S_OK;
}

SEALDLL HRESULT SEALCALL DefParams_CoeffModulus192(uint64_t polyModulusDegree, uint64_t* length, void** coeffs)
{
    IfNullRet(length, E_POINTER);

    vector<SmallModulus> coeffs192;
    try
    {
        coeffs192 = coeff_modulus_192(polyModulusDegree);
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    BuildCoeffPointers(coeffs192, length, coeffs);
    return S_OK;
}

SEALDLL HRESULT SEALCALL DefParams_CoeffModulus256(uint64_t polyModulusDegree, uint64_t* length, void** coeffs)
{
    IfNullRet(length, E_POINTER);

    vector<SmallModulus> coeffs256;
    try
    {
        coeffs256 = coeff_modulus_256(polyModulusDegree);
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    BuildCoeffPointers(coeffs256, length, coeffs);
    return S_OK;
}

SEALDLL HRESULT SEALCALL DefParams_SmallMods60Bit(uint64_t index, void** small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        SmallModulus* sm = new SmallModulus(small_mods_60bit(index));
        *small_modulus = sm;
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL DefParams_SmallMods50Bit(uint64_t index, void** small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        SmallModulus* sm = new SmallModulus(small_mods_50bit(index));
        *small_modulus = sm;
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL DefParams_SmallMods40Bit(uint64_t index, void** small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        SmallModulus* sm = new SmallModulus(small_mods_40bit(index));
        *small_modulus = sm;
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL DefParams_SmallMods30Bit(uint64_t index, void** small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        SmallModulus* sm = new SmallModulus(small_mods_30bit(index));
        *small_modulus = sm;
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL DefParams_DBCMax(int* dbc_max_value)
{
    IfNullRet(dbc_max_value, E_POINTER);

    *dbc_max_value = dbc_max();
    return S_OK;
}

SEALDLL HRESULT SEALCALL DefParams_DBCMin(int* dbc_min_value)
{
    IfNullRet(dbc_min_value, E_POINTER);

    *dbc_min_value = dbc_min();
    return S_OK;
}
