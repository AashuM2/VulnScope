class RiskScorer:
    def __init__(self, results):
        self.results = results

    def calculate_score(self):
        if not self.results:
            return 0
        severity_weights = {'Critical': 40, 'High': 25, 'Medium': 15, 'Low': 5}
        total = sum(severity_weights.get(r.get('severity', 'Low'), 5) for r in self.results)
        return min(100, total)

    def get_grade(self, score):
        if score >= 75:   return 'Critical Risk', '#ff4444'
        elif score >= 50: return 'High Risk',     '#ff8800'
        elif score >= 25: return 'Medium Risk',   '#ffcc00'
        else:             return 'Low Risk',       '#00ff88'
