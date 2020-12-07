package com.onemainfinancial.logstash.plugins.fluent;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;

public class Utils {
    private static final String MD_ALGORITHM = "SHA-512";
    private static Map<String, List<Object>> paths = new HashMap<>();

    private Utils() {
        //no-op
    }

    public static Long getLong(Map<String, Object> config, String key, Long defaultValue) {
        Object v = config.get(key);
        if (v == null) {
            return defaultValue;
        }
        if (v instanceof Long) {
            return (Long) v;
        }
        return Long.parseLong(String.valueOf(v));
    }

    public static Pattern getPattern(String string) {
        if (string == null) {
            return null;
        }
        return Pattern.compile(string);
    }

    public static Object get(Object object, String path) {
        return get(object, getParsedPathFromCache(path), null);
    }

    public static void set(Object object, String path, Object value) {
        set(object, getParsedPathFromCache(path), value);
    }

    private static <T> List<T> setIndex(List<T> list, int index, T value) {
        if (index < 0) {
            index = list.size() + index;
        }
        if (index < 0) {
            index = -index - 1;
        }

        while (list.size() - 1 < index) {
            list.add(null);
        }
        list.set(index, value);
        return list;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static <T> T set(T input, List<Object> path, Object value) {
        Object object = input;
        for (int start = 0, l = path.size(), last = l - 1; start < l; start++) {
            Object currentPath = path.get(start);
            boolean isList = object instanceof List;
            if (start == last) {
                if (isList && currentPath instanceof Integer) {
                    setIndex(((List) object), (Integer) currentPath, value);
                } else {
                    ((Map) object).put(currentPath, value);
                }
                return input;
            }
            Object nextPath = path.get(start + 1);
            boolean nextIsArray = nextPath instanceof Integer;
            if (isList && currentPath instanceof Integer) {
                int i = ((Integer) currentPath);
                List<Object> list = (List) object;
                if (i < 0) {
                    i = list.size() + i;
                }

                if (list.size() - 1 < i) {
                    if (nextPath instanceof Integer) {
                        setIndex(list, i, new ArrayList<>());
                    } else {
                        setIndex(list, i, new HashMap<>());
                    }
                } else {

                    Object nextObject = list.get(i);
                    boolean nextIsList = nextObject instanceof List;
                    if (nextIsArray && !nextIsList) {
                        setIndex(list, i, new ArrayList<>());
                    } else if (!nextIsArray && !(nextObject instanceof Map)) {
                        setIndex(list, i, new HashMap<>());
                    }
                }
                object = list.get(i);
            } else if (object instanceof Map) {
                Map<Object, Object> map = (Map) object;
                if (!map.containsKey(currentPath)) {
                    if (nextIsArray) {
                        map.put(currentPath, new ArrayList<>());
                    } else {
                        map.put(currentPath, new HashMap<>());
                    }
                } else {
                    Object nextObject = map.get(currentPath);
                    boolean nextIsList = nextObject instanceof List;

                    if (nextIsArray && !nextIsList) {
                        map.put(currentPath, new ArrayList<>());
                    } else if (!nextIsArray && !(nextObject instanceof Map)) {
                        map.put(currentPath, new HashMap<>());
                    }
                }
                object = map.get(currentPath);
            } else {
                throw new IllegalArgumentException("Cannot set path " + currentPath + " in " + object);
            }
        }
        return input;
    }

    public static <T> T get(Object object, List<Object> keys, Object defaultValue) {
        for (Object key : keys) {
            if (object instanceof Map) {
                if (!((Map) object).containsKey(key)) {
                    return (T) defaultValue;
                }
                object = ((Map) object).get(key);
            } else if (object instanceof List) {
                if (key instanceof String) {
                    try {
                        key = Integer.parseInt((String) key);
                    } catch (Exception e) {
                        return (T) defaultValue;
                    }
                }
                int index = ((Integer) key);
                List<?> list = ((List<?>) object);
                if (index < 0) {
                    index = list.size() - index;
                }
                try {
                    object = ((List) object).get(index);
                } catch (IndexOutOfBoundsException e) {
                    return (T) defaultValue;
                }
            } else {
                return (T) defaultValue;
            }
        }
        return (T) object;
    }

    public static List<Object> getParsedPathFromCache(String key) {
        if (paths.containsKey(key)) {
            return paths.get(key);
        }
        if (key == null) {
            return null;
        }
        paths.put(key, parsePath(key));
        return paths.get(key);
    }

    private static List<Object> parsePath(String key) {
        List<Object> list = new ArrayList<>();
        boolean escaped = false;
        StringBuilder sb = new StringBuilder();
        for (char c : key.toCharArray()) {
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else if (c == '/') {
                escaped = true;
            } else if (c == '[') {
                if (sb.length() > 0) {
                    list.add(sb.toString());
                    sb.setLength(0);
                }
            } else if (c == ']') {
                if (sb.length() > 0) {
                    list.add(sb.toString());
                    sb.setLength(0);
                }
            } else {
                sb.append(c);
            }
        }
        if (sb.length() > 0) {
            list.add(sb.toString());
        }
        for (int i = 0; i < list.size(); i++) {
            try {
                list.set(i, Integer.parseInt((String)list.get(i)));
            } catch (Exception e) {
                //no-op
            }
        }
        return list;
    }


    public static String getHexDigest(byte[]... updates) {
        try {
            MessageDigest md = MessageDigest.getInstance(MD_ALGORITHM);
            StringBuilder hexString = new StringBuilder();
            for (byte[] b : updates) {
                md.update(b);
            }
            for (byte b : md.digest()) {
                String hex = Integer.toHexString(0xFF & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }


    public static byte[] generateSalt() {
        byte[] b = new byte[16];
        new Random().nextBytes(b);
        return b;
    }
}
