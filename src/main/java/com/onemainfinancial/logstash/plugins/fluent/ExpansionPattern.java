package com.onemainfinancial.logstash.plugins.fluent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExpansionPattern {
    private static final Map<String, List<ExpansionPattern>> expansions = new HashMap<>();
    public final int startIndex;
    public final int endIndex;
    public final String field;

    public ExpansionPattern(int startIndex, int endIndex, String field) {
        this.field = field;
        this.endIndex = endIndex;
        this.startIndex = startIndex;
    }

    public static String expand(String key, Map<String, Object> event) {
        List<ExpansionPattern> e = getExpansions(key);
        if (e.isEmpty()) {
            return key;
        }
        StringBuilder sb = new StringBuilder();
        int lastIndex = 0;
        for (ExpansionPattern p : e) {
            sb.append(key, lastIndex, p.startIndex);
            Object s = Utils.get(event,p.field);
            if (s == null) {
                s = "";
            }
            sb.append(s);
            lastIndex = p.endIndex;
        }
        sb.append(key, lastIndex, key.length());
        return sb.toString();
    }

    public static List<ExpansionPattern> getExpansions(String key) {

        List<ExpansionPattern> expansionPatterns = expansions.get(key);
        if (expansionPatterns != null) {
            return expansionPatterns;
        }
        expansionPatterns = new ArrayList<>();
        char[] chars = key.toCharArray();
        boolean patternFound = false;
        int startIndex = 0;
        boolean escaped = false;
        StringBuilder builder = new StringBuilder();
        int skip = 0;
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (skip > 0) {
                skip--;
            } else if (escaped) {
                escaped = false;
            } else {
                if (c == '\\') {
                    escaped = true;
                }
                if (patternFound && c == '}') {
                    patternFound = false;
                    expansionPatterns.add(new ExpansionPattern(startIndex, i + 1, builder.toString()));
                    builder.setLength(0);
                } else if (!patternFound && (i < chars.length - 1 && c == '%' && chars[i + 1] == '{')) {
                    patternFound = true;
                    startIndex = i;
                    skip = 1;
                } else if (patternFound) {
                    builder.append(c);
                }
            }
        }

        expansions.put(key, expansionPatterns);
        return expansionPatterns;
    }

    @Override
    public String toString() {
        return "[" + field + "][" + startIndex + ":" + endIndex + "]";
    }
}
