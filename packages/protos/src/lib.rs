#[allow(unused, unused_imports)]
use quote::{ToTokens, quote};
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, AttributeArgs, Meta, NestedMeta, /* DataEnum, DeriveInput, MetaList, */};

/* 


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



 */






#[proc_macro_attribute]
pub fn session_action(metadata: TokenStream, input: TokenStream) -> TokenStream {
    // Parse the macro argument
    let args = parse_macro_input!(metadata as AttributeArgs);
    let non_session_ty = match args.first() {
        Some(NestedMeta::Meta(Meta::Path(path))) => path.clone(),
        _ => {
            return syn::Error::new_spanned(
                quote! { #[session_action(..)] },
                "expected #[session_action(ExecuteAccountMsg)] with exactly one type argument",
            )
            .to_compile_error()
            .into();
        }
    };
    let act_id = non_session_ty.get_ident().clone().unwrap();
    // println!("act_id: {:?}", act_id);
    
    // Parse the enum itself
    let mut input_enum = parse_macro_input!(input as syn::ItemEnum);
    let enum_ident = &input_enum.ident;

    // Add `SessionActions` variant to the enum
    input_enum.variants.push(syn::Variant {
        ident: syn::Ident::new("SessionActions", enum_ident.span()),
        fields: syn::Fields::Unnamed(syn::FieldsUnnamed {
            paren_token: Default::default(),
            unnamed: std::iter::once(syn::Field {
                attrs: vec![],
                vis: syn::Visibility::Inherited,
                ident: None,
                colon_token: None,
                ty: syn::parse_quote!(::saa_wasm::SessionAction<#act_id>),
            })
            .collect(),
        }),
        discriminant: None,
        attrs: vec![],
    });



    // Combine the updated enum and impl
    let output = quote! {
        #input_enum
        //#trait_impl
    };

    output.into()
}


#[proc_macro_attribute]
pub fn session_query(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(metadata as AttributeArgs);

    if args.len() != 1 {
        return syn::Error::new_spanned(
            quote! { #[session_query(..)] },
            "expected #[session_query(ExecuteMsg)] with exactly one argument",
        )
        .to_compile_error()
        .into();
    }

    let action_msg_ty = match &args[0] {
        syn::NestedMeta::Meta(syn::Meta::Path(path)) => path.clone(),
        other => {
            return syn::Error::new_spanned(
                other,
                "expected identifier like `ExecuteMsg`"
            )
            .to_compile_error()
            .into();
        }
    };

    let mut input_enum = match syn::parse::<syn::ItemEnum>(input) {
        Ok(e) => e,
        Err(err) => return err.to_compile_error().into(),
    };

    // Add #[derive(QueryResponses)]
    input_enum.attrs.push(parse_quote! {
        #[derive(::saa_schema::QueryResponses)]
    });

    // Add SessionQueries variant using Self in generic position
    input_enum.variants.push(parse_quote! {
        #[returns(::saa_wasm::QueryResTemplate)]
        SessionQueries(::saa_wasm::SessionQueryMsg<Self>)
    });

    let enum_ident = &input_enum.ident;
    let generics = &input_enum.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let trait_impl = quote! {
        impl #impl_generics ::saa_wasm::QueryUsesActions for #enum_ident #ty_generics #where_clause {
            type ActionMsg = #action_msg_ty;
        }
    };

    quote! {
        #input_enum
        #trait_impl
    }
    .into()
}

