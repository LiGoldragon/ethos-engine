//! The authority-bound ingestion path: parsed Ethos declarations → the currently wired
//! legacy central authority → canonical [`EncodedUniverse`].
//!
//! Both front ends — the LEGACY `schema-language` migration and the NATIVE `core-ethos`
//! six-slot document decode — land in the same [`ParsedEthos`]: stringless encoded
//! declarations plus the name space they were parsed against. From there the path is
//! identical for both, which is exactly what makes the equivalence witness meaningful:
//! compute one [`DeclaredIdentity`] per declaration, bind-or-mint them against the one
//! currently wired central authority (`sema-storage`), and build the universe from its
//! assignment via [`EncodedUniverse::from_assignment`]. Because that build re-stamps every
//! interior name into a canonical order, two ingestions of one declared Ethos unit that
//! received the same assignment produce byte-identical encoded content.
//!
//! The self-contained migration in [`crate::Dispatch`] (the `IngestTypeEthos` request)
//! remains a compatibility path over the frozen central-storage schema archive. It never
//! consults the identity authority, so its identifiers remain parse-order interned rather
//! than authority-assigned. This authority-bound path is the existing online witness.
//!
//! LEAN `declared-key-and-shape-from-text` (load-bearing): a parsed declaration's bind-
//! or-mint request keys on its RESOLVED declared name (`DeclaredKey` = the name spelling
//! bytes) and fingerprints its RESOLVED structure (`DeclaredShape` = blake3 over role,
//! visibility, kind, and each field/variant's resolved name and resolved reference shape).
//! Resolving through the front end's name table — never folding raw `Identifier` integers
//! — is what makes both the key and the shape a function of the DECLARED content, so the
//! two front ends agree on them for one source. Revision trigger: an authoring surface
//! carrying an explicit per-declaration bind/mint marker distinct from the name.
//! (The elided-string-field spelling ruling of bead .31 has since landed — the derived
//! name canonicalises to `string` on both front ends — and this LEAN held unchanged,
//! because it already resolves field names through each front end's name table rather
//! than folding raw identifiers.)

use content_identity::IdentityHasher;
use core_ethos::declaration::{EncodedDeclaration, EncodedField, EncodedVariant};
use core_ethos::{
    AssignedKind, AssignedMember, BuiltinReference, DeclarationRole, ENCODED_UNIVERSE, EncodedEnum,
    EncodedEthos, EncodedNewtype, EncodedReference, EncodedStruct, EncodedType, EncodedUniverse,
    ScalarSlot, TextualError, TextualEthos, UniverseError, Visibility,
};
use name_table::{IdentifierNamespace, Name, NameTable, NameTableError};
use signal_sema_storage::{
    BoundIdentities, DeclaredIdentity, DeclaredKey, DeclaredShape, IdentityIntent,
};

use crate::legacy_ingest::{LegacyIngestError, LegacySchemaIngest};

/// A failure of the authority-bound ingestion path.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityIngestError {
    #[error("legacy front end: {0}")]
    Legacy(#[from] LegacyIngestError),
    #[error("native front end: {0}")]
    Native(#[from] TextualError),
    #[error("name resolution: {0}")]
    Names(#[from] NameTableError),
    #[error("universe build: {0}")]
    Universe(#[from] UniverseError),
    #[error("the authority bound no identity for declared key {0:?}")]
    UnboundDeclaration(Vec<u8>),
    #[error("the legacy authority assigned identity {0}, outside Ethos's u16 local space")]
    AssignedIdentityOutOfRange(u32),
    #[error("the legacy authority left no local identity available for Ethos builtin priors")]
    BuiltinIdentitySpaceExhausted,
}

/// One Ethos unit parsed from a single front end: its stringless declarations and
/// the name space they were parsed against. The two constructors are the two front ends;
/// every method below is front-end agnostic.
pub struct ParsedEthos {
    ethos: EncodedEthos,
    names: NameTable,
}

impl ParsedEthos {
    /// Parse through the LEGACY `schema-language` front end, migrated into EncodedEthos.
    pub fn from_legacy(text: &str) -> Result<Self, AuthorityIngestError> {
        let migration = LegacySchemaIngest::migrate_text(text)?;
        Ok(Self {
            ethos: migration.ethos,
            names: migration.names,
        })
    }

    /// Parse through the NATIVE front end: `core-ethos`'s six-slot document decode.
    pub fn from_native(text: &str) -> Result<Self, AuthorityIngestError> {
        // `Schema` is the exact namespace spelling in the current pre-identity
        // name-table pin; it names Ethos-owned entries here and is not an engine alias.
        let mut names = NameTable::new(IdentifierNamespace::Schema);
        let ethos = TextualEthos::ethos_document()?.decode_document(text, &mut names)?;
        Ok(Self { ethos, names })
    }

    pub fn ethos(&self) -> &EncodedEthos {
        &self.ethos
    }

    pub fn names(&self) -> &NameTable {
        &self.names
    }

    /// The bind-or-mint declaration set for this parsed Ethos unit: one
    /// [`DeclaredIdentity`]
    /// per declaration, keyed by resolved declared name, fingerprinted by resolved
    /// structural shape, all [`IdentityIntent::MintOrBind`]. Presented in parse order;
    /// the authority binds by key, so a re-presentation under the same whole returns the
    /// same identities regardless of the order either front end parsed.
    pub fn declared_identities(&self) -> Result<Vec<DeclaredIdentity>, AuthorityIngestError> {
        self.ethos
            .declarations()
            .iter()
            .map(|declaration| {
                Ok(DeclaredIdentity {
                    key: self.declared_key(declaration)?,
                    shape: self.declared_shape(declaration)?,
                    intent: IdentityIntent::MintOrBind,
                })
            })
            .collect()
    }

    /// Build the canonical [`EncodedUniverse`] from the authority's reply: one assigned
    /// member per declaration at the authority's local identity, then
    /// [`EncodedUniverse::from_assignment`] re-stamps every interior name into a canonical
    /// order. The built universe's content identity is a pure function of (assignment,
    /// declaration content) — so two front ends bound to one authority build identical
    /// encoded Ethos content.
    pub fn build_universe(
        &self,
        bound: &BoundIdentities,
    ) -> Result<EncodedUniverse, AuthorityIngestError> {
        let mut assigned = self
            .ethos
            .declarations()
            .iter()
            .map(|declaration| {
                let key = self.declared_key(declaration)?;
                let assigned = bound
                    .assignments
                    .iter()
                    .find(|assignment| assignment.key == key)
                    .ok_or_else(|| AuthorityIngestError::UnboundDeclaration(key.0.clone()))?
                    .identity
                    .0;
                let local = u16::try_from(assigned)
                    .map_err(|_| AuthorityIngestError::AssignedIdentityOutOfRange(assigned))?;
                Ok((local, declaration))
            })
            .collect::<Result<Vec<_>, AuthorityIngestError>>()?;
        assigned.sort_by_key(|(local, _)| *local);

        // Preserve the compatibility path's canonicalization: declaration names are
        // interned by assigned local first, then each body is walked positionally.
        // Neither source traversal nor either front end's private IDs reach the result.
        let mut names = NameTable::new(IdentifierNamespace::Schema);
        let canonical_names = assigned
            .iter()
            .map(|(_, declaration)| {
                let spelling = self.names.resolve(declaration.identifier())?.clone();
                Ok(names.intern(spelling)?)
            })
            .collect::<Result<Vec<_>, AuthorityIngestError>>()?;
        let mut members = assigned
            .into_iter()
            .zip(canonical_names)
            .map(|((local, declaration), canonical)| {
                Ok(AssignedMember::new(
                    local,
                    canonical,
                    AssignedKind::Declaration(self.restamp_declaration(
                        declaration,
                        canonical,
                        &mut names,
                    )?),
                ))
            })
            .collect::<Result<Vec<_>, AuthorityIngestError>>()?;
        let mut occupied = members
            .iter()
            .map(AssignedMember::local)
            .collect::<std::collections::BTreeSet<_>>();
        for (builtin, slot) in [
            (BuiltinReference::Integer, ScalarSlot::Integer),
            (BuiltinReference::String, ScalarSlot::Text),
            (BuiltinReference::Boolean, ScalarSlot::Boolean),
            (BuiltinReference::Bytes, ScalarSlot::Bytes),
        ] {
            // The frozen authority allocates declarations only. Current EncodedEthos
            // requires its scalar priors in the universe, so this compatibility bridge
            // seats them in otherwise-unused locals from the top of the u16 space.
            let local = (0..=u16::MAX)
                .rev()
                .find(|candidate| !occupied.contains(candidate))
                .ok_or(AuthorityIngestError::BuiltinIdentitySpaceExhausted)?;
            occupied.insert(local);
            let identifier = names.intern(Name::new(builtin.spelling()))?;
            members.push(AssignedMember::new(
                local,
                identifier,
                AssignedKind::ScalarPrimitive(slot),
            ));
        }

        // The frozen authority reply still carries its retired universe number. Current
        // EncodedUniverse is scoped by its typed language tag and member IDs.
        Ok(EncodedUniverse::from_assignment(
            ENCODED_UNIVERSE,
            members,
            names,
        )?)
    }

    fn restamp_declaration(
        &self,
        declaration: &EncodedDeclaration,
        identifier: name_table::Identifier,
        names: &mut NameTable,
    ) -> Result<EncodedDeclaration, AuthorityIngestError> {
        let value = self.restamp_type(declaration.value(), identifier, names)?;
        Ok(match declaration.role() {
            DeclarationRole::DataType => EncodedDeclaration::new(declaration.visibility(), value),
            DeclarationRole::InterfaceInput | DeclarationRole::InterfaceOutput => {
                EncodedDeclaration::interface(declaration.role(), value)
            }
        })
    }

    fn restamp_type(
        &self,
        value: &EncodedType,
        identifier: name_table::Identifier,
        names: &mut NameTable,
    ) -> Result<EncodedType, AuthorityIngestError> {
        Ok(match value {
            EncodedType::Newtype(newtype) => EncodedType::Newtype(EncodedNewtype::new(
                identifier,
                self.restamp_reference(newtype.reference(), names)?,
            )),
            EncodedType::Struct(structure) => EncodedType::Struct(EncodedStruct::new(
                identifier,
                structure
                    .fields()
                    .iter()
                    .map(|field| {
                        Ok(EncodedField::new(
                            self.restamp_identifier(field.identifier(), names)?,
                            self.restamp_reference(field.reference(), names)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, AuthorityIngestError>>()?,
            )),
            EncodedType::Enumeration(enumeration) => EncodedType::Enumeration(EncodedEnum::new(
                identifier,
                enumeration
                    .variants()
                    .iter()
                    .map(|variant| {
                        Ok(EncodedVariant::new(
                            self.restamp_identifier(variant.identifier(), names)?,
                            variant
                                .payload()
                                .map(|payload| self.restamp_reference(payload, names))
                                .transpose()?,
                        ))
                    })
                    .collect::<Result<Vec<_>, AuthorityIngestError>>()?,
            )),
        })
    }

    fn restamp_reference(
        &self,
        reference: &EncodedReference,
        names: &mut NameTable,
    ) -> Result<EncodedReference, AuthorityIngestError> {
        Ok(match reference {
            EncodedReference::String => EncodedReference::String,
            EncodedReference::Integer => EncodedReference::Integer,
            EncodedReference::Boolean => EncodedReference::Boolean,
            EncodedReference::Bytes => EncodedReference::Bytes,
            EncodedReference::Plain(identifier) => {
                EncodedReference::Plain(self.restamp_identifier(*identifier, names)?)
            }
            EncodedReference::SingleTypeApplication {
                projection,
                argument,
            } => EncodedReference::SingleTypeApplication {
                projection: *projection,
                argument: Box::new(self.restamp_reference(argument, names)?),
            },
            EncodedReference::MultiTypeApplication {
                projection,
                arguments,
            } => EncodedReference::MultiTypeApplication {
                projection: *projection,
                arguments: arguments
                    .iter()
                    .map(|argument| self.restamp_reference(argument, names))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            EncodedReference::ValueApplication { projection, value } => {
                EncodedReference::ValueApplication {
                    projection: *projection,
                    value: *value,
                }
            }
        })
    }

    fn restamp_identifier(
        &self,
        identifier: name_table::Identifier,
        names: &mut NameTable,
    ) -> Result<name_table::Identifier, AuthorityIngestError> {
        let spelling = self.names.resolve(identifier)?.clone();
        Ok(names.intern(spelling)?)
    }

    /// The declared key of one declaration — its resolved name spelling (LEAN
    /// `declared-key-is-name`).
    fn declared_key(
        &self,
        declaration: &EncodedDeclaration,
    ) -> Result<DeclaredKey, AuthorityIngestError> {
        let name = self.names.resolve(declaration.identifier())?;
        Ok(DeclaredKey(name.as_str().as_bytes().to_vec()))
    }

    /// The structural fingerprint of one declaration, resolved through the name space so
    /// it is a function of the declared structure rather than of raw interned ids.
    fn declared_shape(
        &self,
        declaration: &EncodedDeclaration,
    ) -> Result<DeclaredShape, AuthorityIngestError> {
        let role_tag = match declaration.role() {
            DeclarationRole::DataType => 0u8,
            DeclarationRole::InterfaceInput => 1,
            DeclarationRole::InterfaceOutput => 2,
        };
        let visibility_tag = match declaration.visibility() {
            Visibility::Public => 0u8,
            Visibility::Private => 1,
        };
        let mut hasher = IdentityHasher::unprimed();
        hasher.update_raw(&[role_tag, visibility_tag]);
        match declaration.value() {
            EncodedType::Newtype(newtype) => {
                hasher.update_raw(&[0]);
                self.fold_reference(&mut hasher, newtype.reference())?;
            }
            EncodedType::Struct(structure) => {
                hasher.update_raw(&[1]);
                hasher.update_raw(&(structure.fields().len() as u64).to_le_bytes());
                for field in structure.fields() {
                    self.fold_field(&mut hasher, field)?;
                }
            }
            EncodedType::Enumeration(enumeration) => {
                hasher.update_raw(&[2]);
                hasher.update_raw(&(enumeration.variants().len() as u64).to_le_bytes());
                for variant in enumeration.variants() {
                    self.fold_variant(&mut hasher, variant)?;
                }
            }
        }
        Ok(DeclaredShape(hasher.finalize_bytes()))
    }

    fn fold_field(
        &self,
        hasher: &mut IdentityHasher,
        field: &EncodedField,
    ) -> Result<(), NameTableError> {
        hasher.update_length_prefixed(self.names.resolve(field.identifier())?.as_str().as_bytes());
        self.fold_reference(hasher, field.reference())
    }

    fn fold_variant(
        &self,
        hasher: &mut IdentityHasher,
        variant: &EncodedVariant,
    ) -> Result<(), NameTableError> {
        hasher.update_length_prefixed(
            self.names
                .resolve(variant.identifier())?
                .as_str()
                .as_bytes(),
        );
        match variant.payload() {
            Some(reference) => {
                hasher.update_raw(&[1]);
                self.fold_reference(hasher, reference)
            }
            None => {
                hasher.update_raw(&[0]);
                Ok(())
            }
        }
    }

    fn fold_reference(
        &self,
        hasher: &mut IdentityHasher,
        reference: &EncodedReference,
    ) -> Result<(), NameTableError> {
        match reference {
            EncodedReference::String => {
                hasher.update_raw(&[0]);
            }
            EncodedReference::Integer => {
                hasher.update_raw(&[1]);
            }
            EncodedReference::Boolean => {
                hasher.update_raw(&[2]);
            }
            EncodedReference::Bytes => {
                hasher.update_raw(&[3]);
            }
            EncodedReference::Plain(identifier) => {
                hasher.update_raw(&[4]);
                hasher.update_length_prefixed(self.names.resolve(*identifier)?.as_str().as_bytes());
            }
            EncodedReference::SingleTypeApplication {
                projection,
                argument,
            } => {
                hasher.update_raw(&[5, *projection as u8]);
                self.fold_reference(hasher, argument)?;
            }
            EncodedReference::MultiTypeApplication {
                projection,
                arguments,
            } => {
                hasher.update_raw(&[6, *projection as u8]);
                hasher.update_raw(&(arguments.len() as u64).to_le_bytes());
                for argument in arguments {
                    self.fold_reference(hasher, argument)?;
                }
            }
            EncodedReference::ValueApplication { projection, value } => {
                hasher.update_raw(&[7, *projection as u8]);
                hasher.update_raw(&value.to_le_bytes());
            }
        }
        Ok(())
    }
}
