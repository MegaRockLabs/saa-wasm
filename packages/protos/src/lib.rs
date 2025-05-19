use quote::{ToTokens, quote};
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, AttributeArgs, DataEnum, DeriveInput, Meta, MetaList, NestedMeta};




fn strum_enum(input: &DeriveInput, attr_args: &[NestedMeta]) -> proc_macro2::TokenStream {
    let ident = &input.ident;

    // Extract optional name(...) argument
    let name_arg = attr_args.iter().find_map(|meta| {
        if let NestedMeta::Meta(Meta::List(MetaList { path, nested, .. })) = meta {
            if path.is_ident("name") {
                return Some(quote! { name(#nested) });
            }
        }
        None
    });

    let maybe_name = if let Some(name) = name_arg {
        quote! { #name, }
    } else {
        quote! {}
    };


    quote! {
        #[derive(
            ::std::fmt::Debug,
            ::std::clone::Clone,
            ::std::cmp::PartialEq,
            ::saa_schema::strum_macros::Display,
            ::saa_schema::strum_macros::EnumDiscriminants,
            ::saa_schema::strum_macros::VariantNames,
            ::saa_schema::serde::Serialize,
            ::saa_schema::serde::Deserialize,
            ::saa_schema::schemars::JsonSchema,
        )]
        #[strum_discriminants(
            #maybe_name
            derive(
                ::saa_schema::serde::Serialize,
                ::saa_schema::serde::Deserialize,
                ::saa_schema::schemars::JsonSchema,
                ::saa_schema::strum_macros::Display,
                ::saa_schema::strum_macros::EnumString,
                ::saa_schema::strum_macros::VariantArray,
                ::saa_schema::strum_macros::AsRefStr
            ),
            serde(deny_unknown_fields, rename_all = "snake_case", crate = "::saa_schema::serde"),
            strum(serialize_all = "snake_case", crate = "::saa_schema::strum"),
            schemars(crate = "::saa_schema::schemars")
        )]
        #[strum(serialize_all = "snake_case", crate = "::saa_schema::strum")]
        #[serde(deny_unknown_fields, rename_all = "snake_case", crate = "::saa_schema::serde")]
        #[schemars(crate = "::saa_schema::schemars")]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #input

        impl ::saa_schema::strum::IntoDiscriminant for Box<#ident> {
            type Discriminant = <#ident as ::saa_schema::strum::IntoDiscriminant>::Discriminant;
            fn discriminant(&self) -> Self::Discriminant {
                (*self).discriminant()
            }
        }

    }
}






fn merge_enum_variants(
    metadata: TokenStream,
    left_ts: TokenStream,
    right_ts: TokenStream,
) -> TokenStream {
    use syn::Data::Enum;

    // Parse metadata and check no args
    let args = parse_macro_input!(metadata as AttributeArgs);
    if let Some(first_arg) = args.first() {
        return syn::Error::new_spanned(first_arg, "macro takes no arguments")
            .to_compile_error()
            .into();
    }

    // Parse left and ensure it's enum
    let mut left: DeriveInput = parse_macro_input!(left_ts);
    let variants = match &mut left.data {
        syn::Data::Enum(DataEnum { variants, .. }) => variants,
        _ => return syn::Error::new(left.ident.span(), "only enums can accept variants")
            .to_compile_error()
            .into(),
    };

    // Parse right and ensure it's enum
    let right: DeriveInput = parse_macro_input!(right_ts);
    let Enum(DataEnum { variants: to_add, .. }) = right.data else {
        return syn::Error::new(left.ident.span(), "only enums can provide variants")
            .to_compile_error()
            .into();
    };

    // Merge variants
    variants.extend(to_add.into_iter());

    // Return modified left
    left.into_token_stream().into()
}





fn generate_session_macro<F>(
    metadata: TokenStream,
    input: TokenStream,
    right_enum: TokenStream,
    extra_impl: F,
    extra_attrs: Option<Vec<syn::Attribute>>,
) -> TokenStream
where
    F: Fn(&syn::Ident, &syn::Generics, &proc_macro2::TokenStream, &proc_macro2::TokenStream, Option<&syn::WhereClause>) -> proc_macro2::TokenStream,
{
    let merged = merge_enum_variants(metadata, input, right_enum);
    // Try to parse the merged stream back into DeriveInput
    let mut parsed = match syn::parse::<DeriveInput>(merged.clone()) {
        Ok(val) => val,
        Err(err) => return err.to_compile_error().into(),
    };

    
    // If extra attributes were provided, extend them on the parsed item
    if let Some(extra) = extra_attrs {
        parsed.attrs.extend(extra);
    }
    
    let enum_name = &parsed.ident;

    let generics = &parsed.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let common_impl = strum_enum(&parsed, &[]);

    let custom_impl = extra_impl(
        enum_name,
        generics,
        &quote! { #impl_generics },
        &quote! { #ty_generics },
        where_clause,
    );

    quote! {
        #common_impl
        #custom_impl
    }
    .into()
}






#[proc_macro_attribute]
pub fn session_action(metadata: TokenStream, input: TokenStream) -> TokenStream {
    generate_session_macro(
        metadata,
        input,
        quote! {
            enum SessionRight {
                SessionActions(Box<::cw_auths::SessionActionMsg<Self>>),
            }
        }
        .into(),
        |enum_name, _generics, impl_generics, ty_generics, where_clause| {
            quote! {
                impl #impl_generics ::cw_auths::SessionActionsMatch for #enum_name #ty_generics #where_clause {
                    fn match_actions(&self) -> Option<::cw_auths::SessionActionMsg<Self>> {
                        match self {
                            Self::SessionActions(msg) => Some((**msg).clone()),
                            _ => None,
                        }
                    }
                }
            }
        },
        None,
    )
}





#[proc_macro_attribute]
pub fn session_query(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(metadata as AttributeArgs);

    // Ensure exactly one argument
    if args.len() != 1 {
        return syn::Error::new_spanned(
            quote! { #[session_query(..)] },
            "expected #[session_query(ExecuteMsg)] with exactly one argument",
        )
        .to_compile_error()
        .into();
    }

    // Extract identifier (e.g., ExecuteMsg)
    let base_msg_ident = match &args[0] {
        syn::NestedMeta::Meta(syn::Meta::Path(path)) => match path.get_ident() {
            Some(ident) => ident.clone(),
            None => {
                return syn::Error::new_spanned(
                    path,
                    "expected identifier like `ExecuteMsg`"
                )
                .to_compile_error()
                .into();
            }
        },
        other => {
            return syn::Error::new_spanned(
                other,
                "expected identifier like `ExecuteMsg`"
            )
            .to_compile_error()
            .into();
        }
    };


    let extra_attrs = Some(vec![parse_quote! {
        #[derive(::saa_schema::QueryResponses)]
    }]);

    // Proceed as before
    generate_session_macro(
        TokenStream::new(),
        input,
        quote! {
            enum SessionRight {
                #[returns(::cw_auths::QueryResTemplate)]
                SessionQueries(Box<::cw_auths::SessionQueryMsg<Self>>),
            }
        }
        .into(),
        move |enum_name, _generics, impl_generics, ty_generics, where_clause| {
            let base_msg = &base_msg_ident;
            quote! {
                impl #impl_generics ::cw_auths::SessionQueriesMatch for #enum_name #ty_generics #where_clause {
                    fn match_queries(&self) -> Option<::cw_auths::SessionQueryMsg<Self>> {
                        match self {
                            Self::SessionQueries(msg) => Some((**msg).clone()),
                            _ => None,
                        }
                    }
                }
                impl #impl_generics ::cw_auths::QueryUsesActions for #enum_name #ty_generics #where_clause {
                    type ActionMsg = #base_msg;
                }
            }
        },
        extra_attrs,
    )
}



