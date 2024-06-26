// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authenticator.proto

#include "authenticator.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)

namespace bftmessages {
class AuthenticatorDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<Authenticator>
      _instance;
} _Authenticator_default_instance_;
}  // namespace bftmessages
namespace protobuf_authenticator_2eproto {
static void InitDefaultsAuthenticator() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::bftmessages::_Authenticator_default_instance_;
    new (ptr) ::bftmessages::Authenticator();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::bftmessages::Authenticator::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<0> scc_info_Authenticator =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsAuthenticator}, {}};

void InitDefaults() {
  ::google::protobuf::internal::InitSCC(&scc_info_Authenticator.base);
}

::google::protobuf::Metadata file_level_metadata[1];
const ::google::protobuf::EnumDescriptor* file_level_enum_descriptors[1];

const ::google::protobuf::uint32 TableStruct::offsets[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::bftmessages::Authenticator, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::bftmessages::Authenticator, fromnodeid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::bftmessages::Authenticator, tonodeid_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::bftmessages::Authenticator, sig_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::bftmessages::Authenticator, sigtype_),
};
static const ::google::protobuf::internal::MigrationSchema schemas[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::bftmessages::Authenticator)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&::bftmessages::_Authenticator_default_instance_),
};

void protobuf_AssignDescriptors() {
  AddDescriptors();
  AssignDescriptors(
      "authenticator.proto", schemas, file_default_instances, TableStruct::offsets,
      file_level_metadata, file_level_enum_descriptors, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_PROTOBUF_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 1);
}

void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\023authenticator.proto\022\013bftmessages\"i\n\rAu"
      "thenticator\022\022\n\nfromNodeId\030\001 \001(\005\022\020\n\010toNod"
      "eId\030\002 \001(\005\022\013\n\003sig\030\003 \001(\014\022%\n\007sigType\030\004 \001(\0162"
      "\024.bftmessages.SigType*\035\n\007SigType\022\t\n\005PKSi"
      "g\020\000\022\007\n\003MAC\020\001B\rZ\013bftmessagesb\006proto3"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 195);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "authenticator.proto", &protobuf_RegisterTypes);
}

void AddDescriptors() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;
}  // namespace protobuf_authenticator_2eproto
namespace bftmessages {
const ::google::protobuf::EnumDescriptor* SigType_descriptor() {
  protobuf_authenticator_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_authenticator_2eproto::file_level_enum_descriptors[0];
}
bool SigType_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}


// ===================================================================

void Authenticator::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int Authenticator::kFromNodeIdFieldNumber;
const int Authenticator::kToNodeIdFieldNumber;
const int Authenticator::kSigFieldNumber;
const int Authenticator::kSigTypeFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

Authenticator::Authenticator()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  ::google::protobuf::internal::InitSCC(
      &protobuf_authenticator_2eproto::scc_info_Authenticator.base);
  SharedCtor();
  // @@protoc_insertion_point(constructor:bftmessages.Authenticator)
}
Authenticator::Authenticator(const Authenticator& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  sig_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.sig().size() > 0) {
    sig_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.sig_);
  }
  ::memcpy(&fromnodeid_, &from.fromnodeid_,
    static_cast<size_t>(reinterpret_cast<char*>(&sigtype_) -
    reinterpret_cast<char*>(&fromnodeid_)) + sizeof(sigtype_));
  // @@protoc_insertion_point(copy_constructor:bftmessages.Authenticator)
}

void Authenticator::SharedCtor() {
  sig_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(&fromnodeid_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&sigtype_) -
      reinterpret_cast<char*>(&fromnodeid_)) + sizeof(sigtype_));
}

Authenticator::~Authenticator() {
  // @@protoc_insertion_point(destructor:bftmessages.Authenticator)
  SharedDtor();
}

void Authenticator::SharedDtor() {
  sig_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void Authenticator::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ::google::protobuf::Descriptor* Authenticator::descriptor() {
  ::protobuf_authenticator_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_authenticator_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const Authenticator& Authenticator::default_instance() {
  ::google::protobuf::internal::InitSCC(&protobuf_authenticator_2eproto::scc_info_Authenticator.base);
  return *internal_default_instance();
}


void Authenticator::Clear() {
// @@protoc_insertion_point(message_clear_start:bftmessages.Authenticator)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  sig_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(&fromnodeid_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&sigtype_) -
      reinterpret_cast<char*>(&fromnodeid_)) + sizeof(sigtype_));
  _internal_metadata_.Clear();
}

bool Authenticator::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:bftmessages.Authenticator)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // int32 fromNodeId = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(8u /* 8 & 0xFF */)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &fromnodeid_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // int32 toNodeId = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(16u /* 16 & 0xFF */)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &tonodeid_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // bytes sig = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(26u /* 26 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadBytes(
                input, this->mutable_sig()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // .bftmessages.SigType sigType = 4;
      case 4: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(32u /* 32 & 0xFF */)) {
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          set_sigtype(static_cast< ::bftmessages::SigType >(value));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:bftmessages.Authenticator)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:bftmessages.Authenticator)
  return false;
#undef DO_
}

void Authenticator::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:bftmessages.Authenticator)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // int32 fromNodeId = 1;
  if (this->fromnodeid() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(1, this->fromnodeid(), output);
  }

  // int32 toNodeId = 2;
  if (this->tonodeid() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(2, this->tonodeid(), output);
  }

  // bytes sig = 3;
  if (this->sig().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::WriteBytesMaybeAliased(
      3, this->sig(), output);
  }

  // .bftmessages.SigType sigType = 4;
  if (this->sigtype() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      4, this->sigtype(), output);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:bftmessages.Authenticator)
}

::google::protobuf::uint8* Authenticator::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:bftmessages.Authenticator)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // int32 fromNodeId = 1;
  if (this->fromnodeid() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(1, this->fromnodeid(), target);
  }

  // int32 toNodeId = 2;
  if (this->tonodeid() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(2, this->tonodeid(), target);
  }

  // bytes sig = 3;
  if (this->sig().size() > 0) {
    target =
      ::google::protobuf::internal::WireFormatLite::WriteBytesToArray(
        3, this->sig(), target);
  }

  // .bftmessages.SigType sigType = 4;
  if (this->sigtype() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      4, this->sigtype(), target);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:bftmessages.Authenticator)
  return target;
}

size_t Authenticator::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:bftmessages.Authenticator)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  // bytes sig = 3;
  if (this->sig().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::BytesSize(
        this->sig());
  }

  // int32 fromNodeId = 1;
  if (this->fromnodeid() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->fromnodeid());
  }

  // int32 toNodeId = 2;
  if (this->tonodeid() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->tonodeid());
  }

  // .bftmessages.SigType sigType = 4;
  if (this->sigtype() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::EnumSize(this->sigtype());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Authenticator::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:bftmessages.Authenticator)
  GOOGLE_DCHECK_NE(&from, this);
  const Authenticator* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const Authenticator>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:bftmessages.Authenticator)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:bftmessages.Authenticator)
    MergeFrom(*source);
  }
}

void Authenticator::MergeFrom(const Authenticator& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:bftmessages.Authenticator)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.sig().size() > 0) {

    sig_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.sig_);
  }
  if (from.fromnodeid() != 0) {
    set_fromnodeid(from.fromnodeid());
  }
  if (from.tonodeid() != 0) {
    set_tonodeid(from.tonodeid());
  }
  if (from.sigtype() != 0) {
    set_sigtype(from.sigtype());
  }
}

void Authenticator::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:bftmessages.Authenticator)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Authenticator::CopyFrom(const Authenticator& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:bftmessages.Authenticator)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Authenticator::IsInitialized() const {
  return true;
}

void Authenticator::Swap(Authenticator* other) {
  if (other == this) return;
  InternalSwap(other);
}
void Authenticator::InternalSwap(Authenticator* other) {
  using std::swap;
  sig_.Swap(&other->sig_, &::google::protobuf::internal::GetEmptyStringAlreadyInited(),
    GetArenaNoVirtual());
  swap(fromnodeid_, other->fromnodeid_);
  swap(tonodeid_, other->tonodeid_);
  swap(sigtype_, other->sigtype_);
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::google::protobuf::Metadata Authenticator::GetMetadata() const {
  protobuf_authenticator_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_authenticator_2eproto::file_level_metadata[kIndexInFileMessages];
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace bftmessages
namespace google {
namespace protobuf {
template<> GOOGLE_PROTOBUF_ATTRIBUTE_NOINLINE ::bftmessages::Authenticator* Arena::CreateMaybeMessage< ::bftmessages::Authenticator >(Arena* arena) {
  return Arena::CreateInternal< ::bftmessages::Authenticator >(arena);
}
}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)
