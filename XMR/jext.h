#pragma once

using namespace rapidjson;

/* This macro brings rapidjson more in line with other libs */
inline const Value* GetObjectMember(const Value& p_obj, const char* p_key)
{
    Value::ConstMemberIterator itr = p_obj.FindMember(p_key);
    if (itr != p_obj.MemberEnd())
        return &(itr->value);
    else
        return nullptr;
}
