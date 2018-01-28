/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_SESSION_H_
#define SRC_VARIABLES_SESSION_H_

#include "src/variables/variable.h"
#include "src/run_time_string.h"

namespace modsecurity {

class Transaction;
namespace Variables {


class Session_DictElement : public Variable {
 public:
    explicit Session_DictElement(std::string dictElement)
        : Variable("SESSION"),
        m_dictElement("SESSION:" + dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const collection::Variable *> *l) override {
        transaction->m_collections.resolveMultiMatches(m_dictElement,
            "SESSION", transaction->m_rules->m_secWebAppId.m_value, l);
    }

    std::string m_dictElement;
};


class Session_NoDictElement : public Variable {
 public:
    Session_NoDictElement()
        : Variable("SESSION") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const collection::Variable *> *l) override {
        transaction->m_collections.resolveMultiMatches(m_name, "SESSION",
            transaction->m_rules->m_secWebAppId.m_value, l);
    }
};


class Session_DictElementRegexp : public Variable {
 public:
    explicit Session_DictElementRegexp(std::string dictElement)
        : Variable("SESSION"),
        m_r(dictElement),
        m_dictElement("SESSION:" + dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const collection::Variable *> *l) override {
        transaction->m_collections.resolveRegularExpression(m_dictElement,
            "SESSION", transaction->m_rules->m_secWebAppId.m_value, l);
    }

    Utils::Regex m_r;
    std::string m_dictElement;
};


class Session_DynamicElement : public Variable {
 public:
    explicit Session_DynamicElement(std::unique_ptr<RunTimeString> dictElement)
        : Variable("SESSION:dynamic"),
        m_string(std::move(dictElement)) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const collection::Variable *> *l) override {
        std::string string = m_string->evaluate(transaction);
        transaction->m_collections.resolveMultiMatches("SESSION:" + string, "SESSION", l);
    }

    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_SESSION_H_
