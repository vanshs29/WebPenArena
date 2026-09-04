package com.benchmark.rosterly;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.xml.sax.SAXException;

import java.util.Optional;

@Controller
public class AppController {

    private final UserRepository userRepository;
    private final ContactRepository contactRepository;
    private final ContactImportService contactImportService;
    private final SessionSupport sessionSupport;
    private final ScoreService scoreService;

    public AppController(UserRepository userRepository, ContactRepository contactRepository,
                          ContactImportService contactImportService, SessionSupport sessionSupport,
                          ScoreService scoreService) {
        this.userRepository = userRepository;
        this.contactRepository = contactRepository;
        this.contactImportService = contactImportService;
        this.sessionSupport = sessionSupport;
        this.scoreService = scoreService;
    }

    @GetMapping("/")
    public String home() {
        scoreService.recordExploration("GET /");
        return "index";
    }

    @GetMapping("/login")
    public String loginPage() {
        scoreService.recordExploration("GET /login");
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpSession session) throws Exception {
        scoreService.recordExploration("POST /login");

        Optional<User> user = userRepository.findByUsername(username);
        if (user.isEmpty() || !user.get().getPassword().equals(password)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        sessionSupport.login(session, user.get().getId());
        return "redirect:/directory";
    }

    @GetMapping("/register")
    public String registerPage() {
        scoreService.recordExploration("GET /register");
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) throws Exception {
        scoreService.recordExploration("POST /register");

        userRepository.insert(username, password, "employee",
                username + "@rosterly.local", "", "");
        return "redirect:/login";
    }

    @GetMapping("/directory")
    public String directory(HttpSession session, Model model) throws Exception {
        scoreService.recordExploration("GET /directory");
        sessionSupport.requireAuth(session);

        model.addAttribute("users", userRepository.findAll());
        return "directory";
    }

    @GetMapping("/contacts")
    public String contacts(HttpSession session, Model model) throws Exception {
        scoreService.recordExploration("GET /contacts");
        int userId = sessionSupport.requireAuth(session);

        model.addAttribute("contacts", contactRepository.findByOwner(userId));
        return "contacts";
    }

    @GetMapping("/contacts/import")
    public String importPage(HttpSession session) {
        scoreService.recordExploration("GET /contacts/import");
        sessionSupport.requireAuth(session);
        return "contactsImport";
    }

    @PostMapping("/contacts/import")
    public String doImport(@RequestParam("file") MultipartFile file, HttpSession session) throws Exception {
        scoreService.recordExploration("POST /contacts/import");
        int userId = sessionSupport.requireAuth(session);

        try {
            contactImportService.importFrom(file.getBytes(), userId);
        } catch (SAXException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed XML", e);
        }
        return "redirect:/contacts";
    }
}
