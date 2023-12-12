use num_bigint::BigUint;
use sync_vm::circuit_structures::byte::IntoBytes as _;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::data_structures::PolyIdentifier;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::lookup_tables::LookupTableApplication;
use sync_vm::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use sync_vm::secp256k1::fq::Fq as Secp256Fq;
use sync_vm::secp256k1::fr::Fr as Secp256Fr;
use sync_vm::{
    circuit_structures::{byte::Byte, utils::can_not_be_false_if_flagged},
    franklin_crypto::{
        self,
        bellman::{
            plonk::better_better_cs::cs::{ConstraintSystem, MainGate, MainGateTerm},
            Engine, Field, GenericCurveAffine, GenericCurveProjective, PrimeField, SqrtField,
            SynthesisError,
        },
        plonk::circuit::{
            allocated_num::{AllocatedNum, Num},
            bigint_new::{
                FieldElement, ReductionStatus, RnsParameters, BITWISE_LOGICAL_OPS_TABLE_NAME,
            },
            boolean::{AllocatedBit, Boolean},
            curve_new::AffinePoint,
            linear_combination::LinearCombination,
            Assignment,
        },
    },
    utils::u64_to_fe,
    vm::{
        partitioner::smart_or,
        primitives::{uint256::UInt256, UInt32, UInt64},
    },
};

// UInt256.inner is private so I have to use this hack
fn uint256_inner<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    uint256: &UInt256<E>,
) -> [UInt64<E>; 4] {
    let bytes = uint256
        .into_le_bytes(cs)
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    let mut inner: [UInt64<E>; 4] = [UInt64::zero(); 4];
    for (i, b) in bytes.chunks_exact(8).enumerate() {
        inner[i] = UInt64::from_bytes_le(cs, b.try_into().unwrap()).unwrap();
    }
    inner
}

fn convert_uint256_to_field_element<'a, E: Engine, F: PrimeField, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    elem: &UInt256<E>,
    rns_strategy: &'a RnsParameters<E, F>,
    exceptions: &mut Vec<Boolean>,
) -> Result<FieldElement<'a, E, F>, SynthesisError> {
    let raw_limbs = uint256_inner(cs, elem)
        .into_iter()
        .map(|x| x.inner)
        .collect::<Vec<Num<E>>>();
    // let raw_limbs = [Default::default(); 4].into_iter().collect::<Vec<Num<E>>>();
    let mut fe = unsafe {
        FieldElement::<E, F>::alloc_from_limbs_unchecked(cs, &raw_limbs, &rns_strategy, false)?
    };
    let is_zero = FieldElement::is_zero(&mut fe, cs)?;
    exceptions.push(is_zero);
    FieldElement::conditionally_select(cs, &is_zero, &FieldElement::one(&rns_strategy), &fe)
}

const CHUNK_BITLEN: usize = 64;
const SECP_B_COEF: u64 = 7;
const EXCEPTION_FLAGS_ARR_LEN: usize = 4;
const X_POWERS_ARR_LEN: usize = 256;

fn ecrecover_precompile_inner_routine<'a, E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    recid: &UInt32<E>,
    r_as_u64x4: &UInt256<E>,
    s_as_u64x4: &UInt256<E>,
    message_hash_as_u64x4: &UInt256<E>,
) -> Result<(Boolean, (UInt256<E>, UInt256<E>)), SynthesisError> {
    // Init parameters
    type G = sync_vm::secp256k1::PointAffine;
    type Base = <G as GenericCurveAffine>::Base;
    type Scalar = <G as GenericCurveAffine>::Scalar;
    use franklin_crypto::plonk::circuit::bigint_new::bigint::repr_to_biguint;
    let secp_p_as_u64x4 = UInt256::<E>::constant(repr_to_biguint::<Secp256Fq>(&Secp256Fq::char()));
    let secp_n_as_u64x4 = UInt256::<E>::constant(repr_to_biguint::<Secp256Fr>(&Secp256Fr::char()));
    let rns_strategy_for_base_field = RnsParameters::<E, Base>::new_optimal(cs, CHUNK_BITLEN);
    let rns_strategy_for_scalar_field = RnsParameters::<E, Scalar>::new_optimal(cs, CHUNK_BITLEN);
    let mut minus_one_in_external_field = {
        let one_in_external_field = FieldElement::<E, Base>::one(&rns_strategy_for_base_field);
        one_in_external_field.negate(cs)?
    };
    let (b_coef_in_external_field, valid_x_in_external_field, valid_t_in_external_field) = {
        let f = |v: u64| FieldElement::constant(u64_to_fe::<Base>(v), &rns_strategy_for_base_field);
        (f(SECP_B_COEF), f(9), f(9 + SECP_B_COEF))
    };

    let mut two = E::Fr::one();
    two.double();
    let two_inv = two.inverse().unwrap();
    let mut minus_one = E::Fr::one();
    minus_one.negate();
    let mut minus_two = minus_one.clone();
    minus_two.double();

    let table = cs.get_table(BITWISE_LOGICAL_OPS_TABLE_NAME)?;
    let dummy = CS::get_dummy_variable();
    let range_of_linear_terms = <CS::MainGate as MainGate<_>>::range_of_linear_terms();
    let mut exception_flags = Vec::with_capacity(EXCEPTION_FLAGS_ARR_LEN);

    // recid = (x_overflow ? 2 : 0) | (secp256k1_fe_is_odd(&r.y) ? 1 : 0)
    // The point X = (x, y) we are going to recover is not known at the start, but it is strongly related to r.
    // This is because x = r + kn for some integer k, where x is an element of the field F_q . In other words, x < q.
    // (here n is the order of group of points on elleptic curve)
    // For secp256k1 curve values of q and n are relatively close, that is,
    // the probability of a random element of Fq being greater than n is about 1/{2^128}.
    // This in turn means that the overwhelming majority of r determine a unique x, however some of them determine
    // two: x = r and x = r + n. If x_overflow flag is set than x = r + n
    let x_overflow = Boolean::Is(AllocatedBit::alloc(
        cs,
        recid.get_value().map(|x| x & 0b10 != 0),
    )?);
    let y_is_odd = Boolean::Is(AllocatedBit::alloc(
        cs,
        recid.get_value().map(|x| x & 0b1 != 0),
    )?);
    let mut lc = LinearCombination::zero();
    // 2 * x_overflow + 1 * y_is_odd - recid = 0
    lc.add_assign_boolean_with_coeff(&x_overflow, two.clone());
    lc.add_assign_boolean_with_coeff(&y_is_odd, E::Fr::one());
    lc.add_assign_number_with_coeff(&recid.inner, minus_one.clone());
    lc.enforce_zero(cs)?;

    // x = r + n if x_overflow else r
    let (r_plus_n_as_u64x4, of) = r_as_u64x4.add(cs, &secp_n_as_u64x4)?;
    let mut x_as_u64x4 =
        UInt256::conditionally_select(cs, &x_overflow, &r_plus_n_as_u64x4, &r_as_u64x4)?;
    let error = Boolean::and(cs, &x_overflow, &of)?;
    exception_flags.push(error);

    // we handle x separately as it is the only element of base field of a curve (no a scalar field element!)
    // check that x < q - order of base point on Secp256 curve
    // if it is not actually the case - mask x to be zero
    let (_res, is_in_range) = x_as_u64x4.sub(cs, &secp_p_as_u64x4)?;
    x_as_u64x4 = x_as_u64x4.mask(cs, &is_in_range)?;
    exception_flags.push(is_in_range.not());
    // let raw_x_limbs = x_as_u64x4
    //     .inner
    let raw_x_limbs = uint256_inner(cs, &x_as_u64x4)
        .into_iter()
        .map(|x| x.inner)
        .collect::<Vec<Num<E>>>();
    let x_fe = unsafe {
        FieldElement::<E, Base>::alloc_from_limbs_unchecked(
            cs,
            &raw_x_limbs,
            &rns_strategy_for_base_field,
            true,
        )?
    };

    let mut r_fe = convert_uint256_to_field_element::<E, Scalar, CS>(
        cs,
        &r_as_u64x4,
        &rns_strategy_for_scalar_field,
        &mut exception_flags,
    )?;
    let mut s_fe = convert_uint256_to_field_element::<E, Scalar, CS>(
        cs,
        &s_as_u64x4,
        &rns_strategy_for_scalar_field,
        &mut exception_flags,
    )?;
    // NB: although it is not strictly an exception we also assume that hash is never zero as field element
    let mut message_hash_fe = convert_uint256_to_field_element::<E, Scalar, CS>(
        cs,
        &message_hash_as_u64x4,
        &rns_strategy_for_scalar_field,
        &mut exception_flags,
    )?;

    // curve equation is y^2 = x^3 + b
    // we compute t = r^3 + b and check if t is a quadratic residue or not.
    // we do this by computing Legendre symbol (t, p) = t^[(p-1)/2] (mod p)
    // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    // n = (p-1)/ 2 = 2^255 - 2^31 - 2^8 - 2^7 - 2^6 - 2^5 - 2^3 - 1
    // we have to compute t^b = t^{2^255} / ( t^{2^31} * t^{2^8} * t^{2^7} * t^{2^6} * t^{2^5} * t^{2^3} * t)
    // if t is not a quadratic residue we return error and replace x by another value that will make
    // t = x^3 + b a quadratic residue
    let mut t = x_fe.square(cs)?;
    t = t.mul(cs, &x_fe)?;
    t = t.add_with_reduction(
        cs,
        &b_coef_in_external_field.clone(),
        ReductionStatus::Loose,
    )?;
    let t_is_zero = FieldElement::is_zero(&mut t, cs)?;
    exception_flags.push(t_is_zero);

    // if t is zero then just mask
    let t = FieldElement::<E, Base>::conditionally_select(
        cs,
        &t_is_zero,
        &valid_t_in_external_field,
        &t,
    )?;

    // array of powers of t of the form t^{2^i} starting from i = 0 to 255
    let mut t_powers = Vec::with_capacity(X_POWERS_ARR_LEN);
    t_powers.push(t);

    for _ in 1..X_POWERS_ARR_LEN {
        let prev = t_powers.last().cloned().unwrap();
        t_powers.push(prev.square(cs)?);
    }
    let mut acc = t_powers[0].clone();
    for idx in [3, 5, 6, 7, 8, 31].into_iter() {
        acc = acc.mul(cs, &t_powers[idx])?;
    }
    let mut legendre_symbol = t_powers[255].div(cs, &acc)?;

    let t_is_nonresidue = FieldElement::<E, Base>::equals(
        cs,
        &mut legendre_symbol,
        &mut minus_one_in_external_field,
    )?;
    exception_flags.push(t_is_nonresidue);
    // unfortunately, if t is found to be a quadratic nonresidue, we can't simply let x to be zero,
    // because then t_new = 7 is again a quadratic nonresidue. So, in this case we let x to be 9, then
    // t = 16 is a quadratic residue
    let x = FieldElement::<E, Base>::conditionally_select(
        cs,
        &t_is_nonresidue,
        &valid_x_in_external_field,
        &x_fe,
    )?;
    let mut t = FieldElement::<E, Base>::conditionally_select(
        cs,
        &t_is_nonresidue,
        &valid_t_in_external_field,
        &t_powers[0],
    )?;
    // we find the value of y, s.t. y^2 = t, and such that y is odd if y_is_odd flag is set and even otherwise
    let y_wit = match (t.get_field_value(), y_is_odd.get_value()) {
        (Some(fr), Some(y_is_odd)) => {
            let mut tmp = fr
                .sqrt()
                .expect(&format!("should be a quadratic residue: {}", fr));
            let tmp_is_odd = tmp.into_repr().as_ref()[0] & 1u64 != 0;
            if tmp_is_odd ^ y_is_odd {
                tmp.negate();
            }
            Some(tmp)
        }
        (_, _) => None,
    };
    let (y, y_decomposition) =
        FieldElement::<E, Base>::alloc_ext(cs, y_wit, &rns_strategy_for_base_field)?;
    {
        // enforce that y^2 == t
        let mut y_squared = y.square(cs)?;
        FieldElement::<E, Base>::enforce_equal(cs, &mut t, &mut y_squared)?;
    }
    {
        // enforce that y is odd <=> y_is_odd flag is set
        // this equal to the constraint: (lowest_limb - y_is_odd) / 2 is range [0, 1 << RANGE_TABLE_WIDTH)
        // let q = (lowest_limb - y_is_odd) / 2, then 2*q + y_odd = lowest_limb
        // we construct the following gate: [lowest_limb, q, q_and_lowest_limb, y_is_odd]
        // NOTE: the whole trick works only if we use BITWISE_XOR table as our range table
        let a = y_decomposition.get_vars()[0];
        let b = AllocatedNum::alloc(cs, || {
            let mut tmp = a.get_value().grab()?;
            tmp.sub_assign(&y_is_odd.get_value_in_field::<E>().grab()?);
            tmp.mul_assign(&two_inv);
            Ok(tmp)
        })?;

        let a_xor_b = match (a.get_value(), b.get_value()) {
            (Some(a_val), Some(b_val)) => {
                let res = table.query(&[a_val, b_val])?;
                AllocatedNum::alloc(cs, || Ok(res[0]))?
            }
            (_, _) => AllocatedNum::alloc(cs, || Err(SynthesisError::AssignmentMissing))?,
        };

        // we construct the following gate: [lowest_limb, q, q_and_lowest_limb, y_is_odd] := [a, b, c, d]
        // 2 * b = a - d => a - 2 * b - d = 0
        let y_is_odd_var = y_is_odd.get_variable().unwrap().get_variable();
        let vars = [
            a.get_variable(),
            b.get_variable(),
            a_xor_b.get_variable(),
            y_is_odd_var,
        ];
        let coeffs = [E::Fr::one(), minus_two.clone(), E::Fr::zero(), minus_one];

        cs.begin_gates_batch_for_step()?;
        cs.apply_single_lookup_gate(&vars[..table.width()], table.clone())?;

        let gate_term = MainGateTerm::new();
        let (_, mut gate_coefs) = CS::MainGate::format_term(gate_term, dummy)?;
        for (idx, coef) in range_of_linear_terms.clone().zip(coeffs.iter()) {
            gate_coefs[idx] = *coef;
        }

        let mg = CS::MainGate::default();
        cs.new_gate_in_batch(&mg, &gate_coefs, &vars, &[])?;
        cs.end_gates_batch_for_step()?;
    }

    // now we are going to compute the public key Q = (x, y) determined by the formula:
    // Q = (s * X - hash * G) / r which is equivalent to r * Q = s * X - hash * G
    // current implementation of point by scalar multiplications doesn't support multiplication by zero
    // so we check that all s, r, hash are not zero (as FieldElements):
    // if any of them is zero we reject the signature and in circuit itself replace all zero variables by ones
    let mut x_point = unsafe { AffinePoint::<E, G>::from_xy_unchecked(x, y) };
    let s_x = x_point.mul_by_scalar_for_prime_order_curve(cs, &mut s_fe)?;

    let mut generator = AffinePoint::<E, G>::constant(G::one(), &rns_strategy_for_base_field);
    let hash_g = generator.mul_by_scalar_for_prime_order_curve(cs, &mut message_hash_fe)?;

    // rhs = s * X - hash * G
    let mut rhs_proj = s_x.sub(cs, &hash_g)?;
    let (mut rhs_affine, is_point_at_infty) =
        rhs_proj.convert_to_affine_or_default(cs, &generator)?;
    exception_flags.push(is_point_at_infty);

    // q_wit = rhg / r
    let q_wit: Option<G> = match (r_fe.get_field_value(), rhs_affine.get_value()) {
        (Some(r_val), Some(pt)) => {
            // Q = 1/r * pt
            let r_inv_val = r_val.inverse().unwrap();
            let mut res = pt.into_projective();
            GenericCurveProjective::mul_assign(&mut res, r_inv_val.into_repr());
            Some(res.into_affine())
        }
        _ => None,
    };
    let (mut q, q_x_chunks, q_y_chunks) =
        AffinePoint::alloc_ext(cs, q_wit, &rns_strategy_for_base_field)?;
    q.enforce_if_normalized(cs)?;

    // lhs = r * Q
    let lhs_proj = q.mul_by_scalar_for_prime_order_curve(cs, &mut r_fe)?;
    // NB: we assume that the difference is NEVER point at infinity
    // it is justified by the fact their difference must be a public key Q which is never point at infinity
    let mut lhs_affine = unsafe { lhs_proj.convert_to_affine(cs)? };
    // AffinePoint::<E, G>::enforce_equal(cs, &mut lhs_affine, &mut rhs_affine)?;

    let any_exception = smart_or(cs, &exception_flags[..])?;
    let comparison_result = AffinePoint::<E, G>::equals(cs, &mut lhs_affine, &mut rhs_affine)?;
    // if no exceptions have happened then LHS == RHS must hold
    can_not_be_false_if_flagged(cs, &comparison_result, &any_exception.not())?;

    let mut q_x_chunks_be: Vec<_> = q_x_chunks
        .get_vars()
        .into_iter()
        .map(|el| Byte::from_num_unconstrained(cs, Num::Variable(*el)))
        .collect();
    q_x_chunks_be.reverse();
    let mut q_y_chunks_be: Vec<_> = q_y_chunks
        .get_vars()
        .into_iter()
        .map(|el| Byte::from_num_unconstrained(cs, Num::Variable(*el)))
        .collect();
    q_y_chunks_be.reverse();

    fn convert_bytes_to_uint256<E: Engine, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        bytes: &[Byte<E>],
        mask: &Boolean,
    ) -> Result<UInt256<E>, SynthesisError> {
        let mut chunks_be_arr = [Byte::empty(); 32];
        chunks_be_arr.copy_from_slice(&bytes[..]);
        let uint256 = UInt256::from_be_bytes_fixed(cs, &chunks_be_arr)?;
        let uint256 = uint256.mask(cs, mask)?;
        Ok(uint256)
    }

    let x_uint256 = convert_bytes_to_uint256(cs, &q_x_chunks_be[..], &any_exception.not())?;
    let y_uint256 = convert_bytes_to_uint256(cs, &q_y_chunks_be[..], &any_exception.not())?;

    // let it = q_x_chunks_be.into_iter().chain(q_y_chunks_be.into_iter());
    // let it_bytes = it
    //     .map(|el| el.get_byte_value())
    //     .filter(|el| el.is_some())
    //     .map(|el| el.unwrap())
    //     .collect::<Vec<_>>();
    // println!("it_bytes len is: {:?}", it_bytes.len());
    // println!("it_bytes: {:}", hex::encode(&it_bytes[..]));

    Ok((any_exception.not(), (x_uint256, y_uint256)))
}

#[test]
fn test_ecdsa_circuit() {
    use pairing::bn256::{Bn256, Fr};
    use sync_vm::franklin_crypto::bellman::{
        kate_commitment::{Crs, CrsForMonomialForm},
        plonk::better_better_cs::{
            cs::{
                Circuit, PlonkCsWidth4WithNextStepParams, ProvingAssembly, SetupAssembly,
                Width4MainGateWithDNext,
            },
            setup::VerificationKey,
            verifier::verify,
        },
        worker::Worker,
    };

    let circuit = TestCircuit::<Bn256> {
        _marker: std::marker::PhantomData,
    };

    let worker = Worker::new();

    let (setup, crs) = {
        let mut assembly = SetupAssembly::<
            Bn256,
            PlonkCsWidth4WithNextStepParams,
            SelectorOptimizedWidth4MainGateWithDNext,
        >::new();
        circuit.synthesize(&mut assembly).expect("must work");
        println!("circuit contains {} gates", assembly.n());
        assert!(assembly.is_satisfied());
        assembly.finalize();
        println!("Setup finalize Done");
        // Generate CRS
        // WARN: in production environment, CRS shouldn't be generated on the fly but rather downloaed from trusted sourcde.
        let crs_mons = {
            // let size = assembly.n().next_power_of_two();
            // println!("power of CRS size = {}", size);
            // Crs::<Bn256, CrsForMonomialForm>::crs_42(size, &worker)
            let file = std::fs::File::open("crs.txt").unwrap();
            Crs::<Bn256, CrsForMonomialForm>::read(file).unwrap()
        };
        // let mut file = std::fs::File::create("crs.txt").unwrap();
        // crs_mons.write(file).unwrap();
        println!("Load CRS Done");
        let setup = assembly
            .create_setup::<TestCircuit<Bn256>>(&worker)
            .unwrap();
        println!("Creating setup Done");
        (setup, crs_mons)
    };
    println!("Setup Done");
    use sync_vm::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

    // Prove: generate proof
    let proof = {
        let mut assembly = ProvingAssembly::<
            Bn256,
            PlonkCsWidth4WithNextStepParams,
            SelectorOptimizedWidth4MainGateWithDNext,
        >::new();
        circuit.synthesize(&mut assembly).expect("must work");
        println!("Proof synthesize Done");
        assert!(assembly.is_satisfied());
        assembly.finalize();
        println!("Proof finalize Done");
        // assembly
        //     // .create_proof::<SimpleCircuit<Bn256>, RollingKeccakTranscript<Fr>>(
        //     .create_proof::<_, RollingKeccakTranscript<Fr>>(&worker, &setup, &crs, None)
        //     .unwrap()
    };
    println!("Proof Done");
    // Verify
    // let valid = {
    //     let vk = VerificationKey::from_setup(&setup, &worker, &crs).unwrap();
    //     // verify::<Bn256, SimpleCircuit<Bn256>, RollingKeccakTranscript<Fr>>(
    //     verify::<_, _, RollingKeccakTranscript<Fr>>(&vk, &proof, None).unwrap()
    // };
    // println!("Verify Done");

    // assert!(valid);
}

struct TestCircuit<E: Engine> {
    pub _marker: std::marker::PhantomData<E>,
}

impl<E: Engine> Circuit<E> for TestCircuit<E> {
    // type MainGate = Width4MainGateWithDNext;
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Prepare
        use sync_vm::vm::tables::BitwiseLogicTable;
        use sync_vm::vm::VM_BITWISE_LOGICAL_OPS_TABLE_NAME;

        let columns3 = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];

        if cs.get_table(VM_BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
            let name = VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
            let bitwise_logic_table = LookupTableApplication::new(
                name,
                BitwiseLogicTable::new(&name, 8),
                columns3.clone(),
                None,
                true,
            );
            cs.add_table(bitwise_logic_table)?;
        };
        inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, 16)?;

        let values = values_be();
        let mut read_values = [UInt256::zero(); 4];
        let mut read_values_le_bytes = [[Num::zero(); 32]; 4];
        for idx in 0..4 {
            let (u256_value, le_bytes) =
                // err
                UInt256::alloc_from_biguint_and_return_u8_chunks(cs, Some(values[idx].clone()))?;
            read_values[idx] = u256_value;
            read_values_le_bytes[idx] = le_bytes;
        }
        let [message_hash_as_u64x4, _v, r_as_u64x4, s_as_u64x4] = read_values;
        let [_, v_bytes, _, _] = read_values_le_bytes;
        let recid = UInt32::from_num_unchecked(v_bytes[0]);

        let (success, (x, y)) = ecrecover_precompile_inner_routine::<E, CS>(
            cs,
            &recid,
            &r_as_u64x4,
            &s_as_u64x4,
            &message_hash_as_u64x4,
        )?;

        // println!("success is: {:?}", success);
        Ok(())
    }
}

fn values_be() -> [BigUint; 4] {
    use std::str::FromStr;
    fn to_big_uint(str: &str) -> BigUint {
        BigUint::from_str(str).unwrap()
    }
    let r =
        to_big_uint("5435062255911969185044564751338785845653803886346232835019851083603393146935");
    let s = to_big_uint(
        "49781538282467577799697603548552481909321341893343441053257506510015983429509",
    );
    let v = to_big_uint("0");
    let msg_hash = to_big_uint(
        "90146787302024890731796003155630242366640710592305648807484605595975845746530",
    );
    // The corresponding publickey (uncompressed):
    // 1d152307c6b72b0ed0418b0e70cd80e7f5295b8d86f5722d3f5213fbd2394f36b7ce9c3e45905178455900b44abb308f3ef480481a4b2ee3f70aca157fde396a
    // The signing secret key:
    // 3b940b5586823dfd02ae3b461bb4336b5ecbaefd6627aa922efc048fec0c881c
    [msg_hash, v, r, s]
}
