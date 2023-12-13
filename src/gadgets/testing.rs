use pairing::bn256::Bn256;
use sync_vm::{
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::{
                cs::{
                    ConstraintSystem, PlonkCsWidth4WithNextStepAndCustomGatesParams,
                    TrivialAssembly,
                },
                data_structures::PolyIdentifier,
                gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
                lookup_tables::LookupTableApplication,
            },
            SynthesisError,
        },
        plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns,
    },
    vm::{tables::BitwiseLogicTable, VM_BITWISE_LOGICAL_OPS_TABLE_NAME},
};

pub fn create_test_constraint_system() -> Result<
    TrivialAssembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >,
    SynthesisError,
> {
    let (mut cs, _, _) = sync_vm::testing::create_test_artifacts_with_optimized_gate();
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
    inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16)?;
    Ok(cs)
}
