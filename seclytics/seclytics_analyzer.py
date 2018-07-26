#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from seclytics import Seclytics
from seclytics.exceptions import InvalidAccessToken, OverQuota


class SeclyticsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.token = self.get_param(
            'config.token', None, 'Missing Seclytics access token')
        self.type = self.get_param(
            'config.type', None, 'Type parameter is missing')
        self.seclytics = Seclytics(access_token=self.token)

    def run(self):
        query = self.get_data()
        try:
            if self.data_type == 'ip':
                report = self.seclytics.ip(query)
            elif self.data_type == 'domain':
                report = self.seclytics.host(query)

            self.report({
                'type': self.data_type,
                'query': query,
                'report': report.intel
            })

        except InvalidAccessToken as err:
            self.error(str(err))
        except OverQuota as err:
            self.error(str(err))
        except RuntimeError as err:
            self.error(str(err))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Seclytics"
        predicate = "Analyze"

        report = raw["report"]
        total = len(report["passive_dns"]) if "passive_dns" in report else 0

        if total <= 1:
            value = "{} result".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))
        else:
            level = 'suspicious'
            value = "{} results".format(total)
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    SeclyticsAnalyzer().run()
