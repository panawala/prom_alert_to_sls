#!/usr/bin/python
# -*- coding: UTF-8 -*-
import random
import time
import yaml

from aliyun.log import LogClient
from duration import from_str

ALERT_SEVERITY_CRITICAL = 10
ALERT_SEVERITY_HIGH = 8
ALERT_SEVERITY_MIDDLE = 6
ALERT_SEVERITY_LOW = 4
ALERT_SEVERITY_REPORT = 2


def generate_alert_name():
    timestamp = int(time.time())
    random_id = ''.join([str(random.randint(0, 9)) for i in range(10)])
    return 'alert-{timestamp}-{random_id}'.format(timestamp=timestamp, random_id=random_id)


def map_to_array(labels):
    alert_labels = []
    for key, value in labels.items():
        alert_labels.append({
            'key': key,
            'value': value
        })
    return alert_labels


def prometheus_severity_to_sls(severity):
    critical_candidates = [
        "严重",
        "紧急",
        "critical",
        "disaster",
        "blocker",
        "immediate",
        "fatal",
        "crit",
        "sev0",
        "sev 0",
        "p0",
    ]
    high_candidates = [
        "高",
        "高级",
        "E",
        "H",
        "high",
        "err",
        "error",
        "urgent",
        "major",
        "sev 1",
        "sev1",
        "p1",
    ]
    middle_candidates = [
        "中",
        "中级",
        "告警",
        "M",
        "medium",
        "unknown",
        "warn",
        "warning",
        "not classified",
        "average",
        "normal",
        "sev 2",
        "sev2",
        "p2",
    ]
    low_candidates = [
        "低",
        "低级",
        "L",
        "I",
        "info",
        "information",
        "suggestion",
        "minor",
        "informational",
        "sev 3",
        "sev3",
        "p3",
    ]
    report_candidates = [
        "报告",
        "通知",
        "report",
        "dbg",
        "debug",
        "verbose",
        "trivial",
        "page",
        "ok",
        "sev 4",
        "sev4",
        "p4",
    ]
    severity_map = {}
    for candidate in critical_candidates:
        severity_map[candidate] = ALERT_SEVERITY_CRITICAL
    for candidate in high_candidates:
        severity_map[candidate] = ALERT_SEVERITY_HIGH
    for candidate in middle_candidates:
        severity_map[candidate] = ALERT_SEVERITY_MIDDLE
    for candidate in low_candidates:
        severity_map[candidate] = ALERT_SEVERITY_LOW
    for candidate in report_candidates:
        severity_map[candidate] = ALERT_SEVERITY_REPORT
    return severity_map.get(severity, ALERT_SEVERITY_MIDDLE)


def prometheus_for_to_sls(for_clause):
    if not for_clause:
        return 1
    for_time_delta = from_str(for_clause)
    threshold = int(for_time_delta.total_seconds() / 60)
    return threshold if threshold > 0 else 1


def prometheus_rule_to_sls_alert(group_name,
                                 rule,
                                 region,
                                 metric_project,
                                 metric_store,
                                 action_policy_id,
                                 alert_policy_id='sls.builtin.dynamic'):
    alert_name = rule.get('alert')
    labels = rule.get('labels')
    alert_labels = map_to_array(labels)
    annotations = rule.get('annotations')
    alert_annotations = map_to_array(annotations)
    alert_annotations.append({
        'key': 'value',
        'value': '${value}'
    })
    expr = rule.get('expr')
    query = "* | select promql_query('{expr}') from metrics limit 1000".format(expr=expr)
    threshold = prometheus_for_to_sls(rule.get('for'))
    alert_severity = prometheus_severity_to_sls(labels.get('severity'))
    alert_conf = {
        'type': 'default',
        'version': '2.0',
        'threshold': threshold,
        'dashboard': 'internal-alert-analysis',
        'queryList': [{
            'region': region,
            'project': metric_project,
            'store': metric_store,
            'storeType': 'metric',
            'end': 'absolute',
            'start': '-1m',
            'timeSpanType': 'Truncated',
            'query': query,
            'ui': '{}'
        }],
        'labels': alert_labels,
        'annotations': alert_annotations,
        'groupConfiguration': {
            'type': 'labels_auto',
            'fields': []
        },
        'severityConfigurations': [{
            'evalCondition': {
                'condition': '',
                'countCondition': ''
            },
            'severity': alert_severity,
        }],
        'sendResolved': False,
        'noDataFire': False,
        'noDataSeverity': ALERT_SEVERITY_MIDDLE,
        'policyConfiguration': {
            'alertPolicyId': alert_policy_id,
            'actionPolicyId': action_policy_id,
            'repeatInterval': '1m',
            'useDefault': False
        }
    }

    alert_job = {
        "type": "Alert",
        'name': generate_alert_name(),
        'displayName': '{alert_name} {group_name}'.format(alert_name=alert_name, group_name=group_name),
        'description': alert_name,
        'schedule': {
            'interval': '1m',
            'type': 'FixedRate',
        },
        'configuration': alert_conf,
    }
    return alert_job


def prometheus_rules_to_sls(rule_file_name,
                            region,
                            metric_project,
                            metric_store,
                            action_policy_id,
                            alert_policy_id):
    alert_jobs = []
    with open(rule_file_name, 'r') as f:
        data = yaml.safe_load(f)
        for group in data['groups']:
            rules = group.get('rules')
            group_name = group.get('name')
            for rule in rules:
                if not rule.get('alert'):
                    continue
                alert_job = prometheus_rule_to_sls_alert(group_name,
                                                         rule,
                                                         region,
                                                         metric_project,
                                                         metric_store,
                                                         action_policy_id,
                                                         alert_policy_id)
                alert_jobs.append(alert_job)
    return alert_jobs


def transform_alert_rules(rule_file_name,
                          region,
                          metric_project,
                          metric_store,
                          access_key,
                          access_secret_key,
                          action_policy_id,
                          alert_policy_id
                          ):
    alert_jobs = prometheus_rules_to_sls(rule_file_name,
                                         region,
                                         metric_project,
                                         metric_store,
                                         action_policy_id,
                                         alert_policy_id
                                         )
    endpoint = '{region}.log.aliyuncs.com'.format(region=region)
    client = LogClient(endpoint, access_key, access_secret_key)
    for alert_job in alert_jobs:
        try:
            client.create_alert(metric_project, alert_job)
        except Exception as e:
            print('create alert err, message is:', str(e))
            break


if __name__ == '__main__':
    region = '<region>'
    metric_project = '<metric_project>'
    metric_store = '<metric_store>'
    access_key = '<ak>'
    access_secret_key = '<sk>'
    action_policy_id = '<user define in sls>'
    alert_policy_id = 'sls.builtin.dynamic'
    transform_alert_rules('prometheus-alert.yaml',
                          region,
                          metric_project,
                          metric_store,
                          access_key,
                          access_secret_key,
                          action_policy_id,
                          alert_policy_id)
