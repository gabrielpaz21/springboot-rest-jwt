package net.openwebinars.springboot.restjwt.note.controller;

import lombok.RequiredArgsConstructor;
import net.openwebinars.springboot.restjwt.note.model.Note;
import net.openwebinars.springboot.restjwt.note.repo.NoteRepository;
import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/note")
@RequiredArgsConstructor
public class NoteController {

    private final NoteRepository repository;

    @GetMapping("/")
    public ResponseEntity<List<Note>> getAll(@AuthenticationPrincipal User user) {
        // We use a common method to return the response from all List<Note>
        // return buildResponseOfAList(repository.findAll());
        return buildResponseOfAList(repository.findByAuthor(user.getId().toString()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<Note> getById(@PathVariable Long id) {
        /*
            The ResponseEntity.of method takes an Optional<?> as an argument and returns
             - 200 Ok if Optional.isPresent() == true
             - 404 Not Found if Optional.isEmpty() == true
         */
        return ResponseEntity.of(repository.findById(id));
    }

    @GetMapping("/author/{author}")
    public ResponseEntity<List<Note>> getByAuthor(@PathVariable String author) {
        // We use a common method to return the response from all List<Note>
        return buildResponseOfAList(repository.findByAuthor(author));
    }

    /**
     * This method is used to return the response of a List<Note>
     * @param list List that will come from a query on the repository
     * @return 404 if the list is empty, 200 OK if the list has elements
     */
    private ResponseEntity<List<Note>> buildResponseOfAList(List<Note> list) {

        if (list.isEmpty())
            return ResponseEntity.notFound().build();
        else
            return ResponseEntity.ok(list);


    }

    @PostMapping("/")
    public ResponseEntity<Note> createNewNote(@RequestBody Note note) {

        Note created = repository.save(note);

        URI createdURI = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(created.getId()).toUri();

        /*
            Typically, the correct response to a POST request is 201 Created.
            Additionally, a Location header can be returned with the URI that
            allows us to make the GET request to the newly created resource.
         */
        return ResponseEntity
                .created(createdURI)
                .body(created);

    }

    @PreAuthorize("@noteRepository.findById(#id).orElse(new net.openwebinars.springboot.restjwt.note.model.Note()).author == authentication.principal.getId().toString()")
    @PutMapping("/{id}")
    public ResponseEntity<Note> edit(@PathVariable Long id, @RequestBody Note edited) {

        return ResponseEntity.of(
                repository.findById(id)
                        .map(note -> {
                            note.setTitle(edited.getTitle());
                            note.setContent(edited.getContent());
                            //note.setAuthor(edited.getAuthor());
                            note.setImportant(edited.isImportant());
                            return repository.save(note);
                        }));



    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {

        // We leave this line commented to cause a 500 error if we delete the same resource twice
        //if (repository.existsById(id))
        repository.deleteById(id);

        return ResponseEntity.noContent().build();

    }

}